"""Offline probe: trace ARN -> endpoint host / signing service / auth attrs.

No real AWS request is sent: a `before-send` handler records the fully
signed request and aborts the send with a sentinel exception.
"""
import json
import re
import sys

import botocore
import botocore.config
import botocore.session

print(f'botocore {botocore.__version__}')
try:
    import awscrt  # noqa: F401
    HAS_CRT = True
except ImportError:
    HAS_CRT = False
print(f'awscrt available: {HAS_CRT}\n')

ACCOUNT = '123456789012'
AP = f'arn:aws:s3:us-west-2:{ACCOUNT}:accesspoint/myap'
AP_EAST = f'arn:aws:s3:us-east-1:{ACCOUNT}:accesspoint/myap'
AP_CN = f'arn:aws-cn:s3:cn-north-1:{ACCOUNT}:accesspoint/myap'
AP_GOV = f'arn:aws-us-gov:s3:us-gov-west-1:{ACCOUNT}:accesspoint/myap'
MRAP = f'arn:aws:s3::{ACCOUNT}:accesspoint/mfzq23risjog1.mrap'
MRAP_CN = f'arn:aws-cn:s3::{ACCOUNT}:accesspoint/mfzq23risjog1.mrap'
OUTPOST = (
    f'arn:aws:s3-outposts:us-west-2:{ACCOUNT}:outpost/'
    'op-01234567890123456/accesspoint/myap'
)
OBJ_LAMBDA = f'arn:aws:s3-object-lambda:us-west-2:{ACCOUNT}:accesspoint/myolap'


class AbortSend(Exception):
    pass


def run_case(name, bucket, region, s3_cfg=None, endpoint_url=None,
             use_fips=False, use_dualstack=False):
    cfg_kwargs = {
        'region_name': region,
        's3': s3_cfg or {},
        'use_fips_endpoint': use_fips,
        'use_dualstack_endpoint': use_dualstack,
    }
    config = botocore.config.Config(**cfg_kwargs)
    session = botocore.session.get_session()
    client = session.create_client(
        's3',
        aws_access_key_id='AKIAFAKEFAKEFAKE01',
        aws_secret_access_key='f' * 40,
        config=config,
        endpoint_url=endpoint_url,
    )
    captured = {}

    def capture(request, **kwargs):
        captured['url'] = request.url
        captured['host'] = request.url.split('/')[2]
        captured['auth_type'] = request.context.get('auth_type')
        captured['signing'] = request.context.get('signing')
        captured['authorization'] = request.headers.get('Authorization', b'')
        captured['x_amz_region_set'] = request.headers.get(
            'X-Amz-Region-Set', b'')
        raise AbortSend()

    client.meta.events.register('before-send.s3.*', capture)
    result = {'case': name}
    try:
        client.get_object(Bucket=bucket, Key='probe-key')
        result['error'] = 'UNEXPECTED: request went through'
    except AbortSend:
        authz = captured['authorization']
        if isinstance(authz, bytes):
            authz = authz.decode()
        m = re.search(r'Credential=[^/]+/[^/]+/([^/]+)/([^/]+)/', authz)
        result.update({
            'host': captured['host'],
            'auth_type': captured['auth_type'],
            'signing_ctx': captured['signing'],
            'cred_scope_region': m.group(1) if m else None,
            'cred_scope_service': m.group(2) if m else None,
            'region_set_header': captured['x_amz_region_set'] or None,
            'scheme': authz.split(' ')[0] if authz else None,
        })
    except Exception as e:
        result['error'] = f'{type(e).__name__}: {e}'
    return result


CASES = [
    # name, bucket, client region, s3 config, endpoint_url, fips, dualstack
    ('plain-bucket', 'mybucket', 'us-west-2', None, None, False, False),
    ('ap-same-region', AP, 'us-west-2', None, None, False, False),
    ('ap-cross-region-default', AP, 'us-east-1', None, None, False, False),
    ('ap-cross-region-use-arn-region',
     AP, 'us-east-1', {'use_arn_region': True}, None, False, False),
    ('ap-cross-region-no-arn-region',
     AP, 'us-east-1', {'use_arn_region': False}, None, False, False),
    ('ap-partition-mismatch', AP_CN, 'us-east-1', None, None, False, False),
    ('ap-cn-partition-ok', AP_CN, 'cn-north-1', None, None, False, False),
    ('ap-gov-cross-partition', AP_GOV, 'us-west-2', None, None, False, False),
    ('ap-custom-endpoint',
     AP, 'us-west-2', None, 'https://s3.example.com', False, False),
    ('ap-custom-endpoint-cross-region',
     AP, 'us-east-1', None, 'https://s3.example.com', False, False),
    ('ap-fips-client', AP_EAST, 'us-east-1', None, None, True, False),
    ('ap-accelerate',
     AP, 'us-west-2', {'use_accelerate_endpoint': True}, None, False, False),
    ('ap-dualstack',
     AP, 'us-west-2', {'use_dualstack_endpoint': True}, None, False, False),
    ('mrap-default', MRAP, 'us-west-2', None, None, False, False),
    ('mrap-disabled',
     MRAP, 'us-west-2',
     {'s3_disable_multiregion_access_points': True}, None, False, False),
    ('mrap-partition-mismatch', MRAP, 'cn-north-1', None, None, False, False),
    ('mrap-cn-partition-ok', MRAP_CN, 'cn-north-1', None, None, False, False),
    ('outpost-arn', OUTPOST, 'us-west-2', None, None, False, False),
    ('object-lambda-arn', OBJ_LAMBDA, 'us-west-2', None, None, False, False),
]

results = []
for name, bucket, region, s3_cfg, endpoint_url, fips, dualstack in CASES:
    results.append(run_case(name, bucket, region, s3_cfg, endpoint_url,
                            fips, dualstack))

for r in results:
    print(f"=== {r['case']}")
    for k, v in r.items():
        if k != 'case':
            print(f'    {k}: {v}')
    print()

with open('arn_probe/results.json', 'w') as f:
    json.dump(results, f, indent=2, default=str)
