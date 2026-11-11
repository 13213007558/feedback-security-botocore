# S3 Access Point ARN 签名区域不匹配：离线定位报告

环境：botocore 1.44.0（本仓库基线，与上游 `b57907f` 一致），CPython 3.12，**未安装 awscrt**。
全部结果由 `arn_probe/probe.py` 离线产出（`before-send` 事件记录已签名的请求后中断发送，无任何真实 AWS 请求），原始数据见 `arn_probe/results.json`。

## 1. 从 ARN 到 endpoint / signing region 的完整路径

1. **客户端构造**（`botocore/args.py`）：`ClientArgsCreator` 把客户端区域、`s3` 配置、自定义 endpoint 写入 endpoint 规则内置参数。注意两个默认值不对称：
   - `AWS::S3::UseArnRegion` 默认 **True**（`botocore/args.py:877`）
   - `AWS::S3Control::UseArnRegion` 默认 **False**（`botocore/args.py:880`）
2. **每次请求解析**（`botocore/client.py:1162` `_resolve_endpoint_ruleset` → `botocore/regions.py` `EndpointRulesetResolver.construct_endpoint`）：用 `botocore/data/s3/2006-03-01/endpoint-rule-set-1.json` 对 `Bucket` 参数里的 ARN 做 `aws.parseArn`，产出 endpoint URL 和 `authSchemes`（`signingName` / `signingRegion` / `signingRegionSet`）。区域不一致、partition 不一致、MRAP 被禁用等都在这一步以 `error` 规则拒绝。
3. **认证方案选择**（`botocore/regions.py:691` `auth_schemes_to_signing_ctx`）：把规则集方案名映射到 `botocore/auth.py` 的 `AUTH_TYPE_MAPS`。`sigv4a` 只有在 `HAS_CRT`（装了 awscrt）时才存在于映射表；规则集只给 sigv4a 而没有 CRT 时抛 `MissingDependencyException`（`botocore/regions.py:764-772`），**不会退回 sigv4**。
4. **签名上下文落地**：`request_context['auth_type']` 与 `request_context['signing']`（region、signing_name）写入上下文；`botocore/handlers.py:195` `set_operation_specific_signer` 把 S3 系签名名升级为 `s3v4` / `s3v4a`；sigv4a 的区域集取 `sigv4a_signing_region_set` 配置或规则集给的 `*`（`botocore/handlers.py:252-270`）。
5. 旧版 `S3RegionRedirector`（`botocore/utils.py:2330+`）仍有访问点校验/换 host 逻辑，但 1.44 默认走规则集；它主要在重定向场景兜底。

## 2. 组合实验结果（stub 记录的最终值）

| 组合 | 结果 |
|---|---|
| 普通 bucket，us-west-2 | host `mybucket.s3.us-west-2.amazonaws.com`，sigv4 `s3/us-west-2` |
| AP ARN 同区域 | host `myap-…012.s3-accesspoint.us-west-2.amazonaws.com`，sigv4 `s3/us-west-2` |
| 客户端 us-east-1 + ARN us-west-2，默认（UseArnRegion=True） | host 指向 **ARN 区域**，签名 `s3/us-west-2` —— 跨区域合法，允许 |
| 同上但 `use_arn_region=False` | **拒绝**：`UnsupportedS3AccesspointConfigurationError: region from ARN 'us-west-2' does not match client region 'us-east-1' and UseArnRegion is 'false'` |
| 客户端 aws 分区 + `arn:aws-cn` ARN | **拒绝**：partition 不匹配（`aws` vs `aws-cn`）；`arn:aws-us-gov` 同理 |
| 客户端 cn-north-1 + `arn:aws-cn` ARN | host `…s3-accesspoint.cn-north-1.amazonaws.com.cn`，签名 `s3/cn-north-1` |
| 自定义 endpoint + ARN 同区域 | host `myap-…012.s3.example.com`（保留自定义 host），签名区域 = ARN 区域 |
| **自定义 endpoint + 客户端 us-east-1 + ARN us-west-2** | host 仍是 `s3.example.com`，**签名区域却是 us-west-2** —— 若该 endpoint 实际在 us-east-1，服务端即报签名区域不匹配。这是“bucket 正常、ARN 失败”的最典型根因 |
| 自定义 endpoint + 跨区 ARN + `use_arn_region=False` | **拒绝**（同区域不匹配错误），不会静默签错区域 |
| FIPS 客户端 + 同区 ARN | host `…s3-accesspoint-fips.us-east-1.amazonaws.com`，签名 `s3/us-east-1` |
| Accelerate + ARN | **拒绝**：`Access Points do not support S3 Accelerate` |
| Dualstack + 普通 AP ARN | host `…s3-accesspoint.dualstack.us-west-2…`，允许 |
| Outposts ARN | host 含 outpost id，签名服务名 **`s3-outposts`** |
| Object Lambda ARN | 签名服务名 **`s3-object-lambda`** |
| MRAP ARN（默认） | **拒绝**：`MissingDependencyException: … pip install botocore[crt]`（规则集只提供 sigv4a，本环境无 awscrt，显式报错、无静默退回） |
| MRAP + `s3_disable_multiregion_access_points=True` | **拒绝**：`Multi-Region Access Point ARNs are disabled.` |
| MRAP `arn:aws` + 客户端 cn-north-1 | **拒绝**：partition 不匹配 |
| MRAP `arn:aws-cn` + 客户端 cn-north-1 | 同样 `MissingDependencyException`（分区校验通过后才到签名器选择） |

MRAP 对照（静态确认，因沙箱无法安装 awscrt）：规则集对 MRAP 返回
`{name: sigv4a, signingName: s3, signingRegionSet: ["*"]}`，host 为
`<name>.accesspoint.s3-global.<dnsSuffix>`。装上 `botocore[crt]` 后，`v4a` 进入
`AUTH_TYPE_MAPS`（`botocore/crt/auth.py:621` 的 `CRT_AUTH_TYPE_MAPS`），S3 签名名升级为
`s3v4a`，请求带 `X-Amz-Region-Set: *`，签名方案为 `AWS4-ECDSA-P256-SHA256`。
缺 awscrt 时在 `auth_schemes_to_signing_ctx` 显式抛错——这正是“缺少可选签名实现时给出明确原因”的现有能力，行为已符合要求。

## 3. 结论：哪些该拒绝、哪些该换签名方案

- **应拒绝（现状已拒绝，客户端侧报错）**：跨区域且 `use_arn_region=False`；跨 partition；ARN+Accelerate；MRAP 被禁用；MRAP+FIPS/dualstack；FIPS 伪区域+异区 ARN。
- **应换签名方案**：MRAP → sigv4a（`s3v4a`，区域集 `*`）；Outposts/Object Lambda → 换签名**服务名**（`s3-outposts` / `s3-object-lambda`），仍是 sigv4。
- **跨区域访问本身合法**：`use_arn_region=True`（S3 默认）时 host 与签名区域都切到 ARN 区域，应保留，不要用配置改死。

## 4. 最小配置修正（按症状根因）

1. **自定义 endpoint（VPC endpoint/代理）+ 异区 ARN**：让 endpoint 指向 ARN 所在区域，或把客户端区域改成 ARN 区域。不要靠 `use_arn_region=False` 压过去——那只会变成客户端报错。
2. **共享配置里设了 `s3_use_arn_region=false`**：删掉该设置或改为 `true`（S3 的默认就是 true）。
3. **partition 混用**（如客户端在商业区、ARN 是 `arn:aws-cn`）：为对应 partition 单独建客户端，无配置可绕过。
4. **MRAP**：`pip install botocore[crt]` 提供 sigv4a；确认未设置 `s3_disable_multiregion_access_points`。

## 5. 代码一致性

基线代码与规则集行为一致，未发现需要修改的不一致：
- 拒绝路径全部抛出带明确原因的异常（`UnsupportedS3AccesspointConfigurationError` / `MissingDependencyException`），无静默退回不适用的签名器；
- `use_arn_region` 默认值、partition 校验、MRAP 的 sigv4a 门控均与规则集和 `CRT_SUPPORTED_AUTH_TYPES` 声明一致。
故本报告不改动 botocore 源码；唯一定位的“不匹配”在使用方配置（见第 4 节）。
