#!/usr/bin/env python3
"""Pre-production verification: botocore honors IMDSv2-only configuration.

Runs entirely against a recording fake transport. No network I/O is
performed; the link-local metadata address is never contacted.

What is verified
----------------
1. Token-endpoint failures never silently downgrade to tokenless (IMDSv1)
   metadata requests when ``ec2_metadata_v1_disabled`` is true. The fetcher
   raises ``MetadataRetrievalError`` (credentials) / propagates it (region)
   instead of sending a GET without the ``x-aws-ec2-metadata-token`` header.
2. Default mode (v1 allowed) keeps the documented compatibility fallback:
   403/404/405/read-timeout/connect-errors on the token PUT fall back to a
   tokenless GET; 400 never falls back.
3. Both consumers are covered: credential retrieval
   (``InstanceMetadataFetcher``) and region discovery
   (``InstanceMetadataRegionFetcher``), including when a custom metadata
   endpoint is configured -- the same policy applies there.
4. Config precedence: explicit instance var > environment variable >
   shared config profile > default(False), and both production entry
   points (``create_credential_resolver``, ``IMDSRegionProvider``) wire the
   resolved value into the fetcher they build.

Exit code is 0 only if every check passes. Evidence (every request the
fake transport received) is printed for each scenario.

Usage:
    python scripts/verify_imdsv2_enforcement.py
"""

import io
import json
import os
import sys
import unittest.mock as mock

import botocore.awsrequest
import botocore.session
from botocore.credentials import create_credential_resolver
from botocore.exceptions import (
    ConnectTimeoutError,
    EndpointConnectionError,
    MetadataRetrievalError,
    ReadTimeoutError,
)
from botocore.utils import (
    BadIMDSRequestError,
    IMDSRegionProvider,
    InstanceMetadataFetcher,
    InstanceMetadataRegionFetcher,
)

CUSTOM_ENDPOINT = 'http://imds-proxy.example.internal:8080'
TOKEN_HEADER = 'x-aws-ec2-metadata-token'
TOKEN_PATH = 'latest/api/token'

FAILURES = []


class _Raw(io.BytesIO):
    def stream(self, **kwargs):
        contents = self.read()
        while contents:
            yield contents
            contents = self.read()


def _http_response(url, status, body=b''):
    return botocore.awsrequest.AWSResponse(
        url=url, status_code=status, headers={}, raw=_Raw(body)
    )


class RecordingTransport:
    """Fake transport standing in for URLLib3Session.send.

    Records every prepared request it receives and replays scripted
    outcomes (responses or exceptions) in order. Any request that has no
    scripted outcome left gets a 200 with an empty body so a runaway
    fetcher cannot hang the check.
    """

    def __init__(self, outcomes):
        self._outcomes = list(outcomes)
        self.requests = []

    def send(self, request):
        self.requests.append(request)
        if not self._outcomes:
            return _http_response(request.url, 200, b'')
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    # -- evidence helpers -------------------------------------------------
    def tokenless_gets(self):
        return [
            r
            for r in self.requests
            if r.method == 'GET' and TOKEN_HEADER not in r.headers
        ]

    def describe(self):
        lines = []
        for r in self.requests:
            if r.method == 'PUT':
                kind = 'token-put'
            elif TOKEN_HEADER in r.headers:
                kind = 'v2-get'
            else:
                kind = 'V1-GET(no token)'
            lines.append(f'{r.method} {r.url} [{kind}]')
        return lines


# Token-PUT failure injections required by the verification plan.
def token_failures(base_url):
    url = f'{base_url}/{TOKEN_PATH}'
    return {
        'http-403': _http_response(url, 403),
        'http-404': _http_response(url, 404),
        'http-405': _http_response(url, 405),
        'http-400': _http_response(url, 400),
        'read-timeout': ReadTimeoutError(endpoint_url=url),
        'connect-timeout': ConnectTimeoutError(endpoint_url=url),
        'connection-error': EndpointConnectionError(endpoint_url=url),
    }


def _ok_token(base_url):
    return _http_response(f'{base_url}/{TOKEN_PATH}', 200, b'token-abc')


def _creds_success_outcomes(base_url):
    return [
        _http_response(
            f'{base_url}/latest/meta-data/iam/security-credentials/',
            200,
            b'role-name',
        ),
        _http_response(
            f'{base_url}/latest/meta-data/iam/security-credentials/role-name',
            200,
            json.dumps(
                {
                    'AccessKeyId': 'ak',
                    'SecretAccessKey': 'sk',
                    'Token': 'st',
                    'Expiration': '1970-01-01T00:00:00Z',
                }
            ).encode(),
        ),
    ]


def _region_success_outcomes(base_url):
    return [
        _http_response(
            f'{base_url}/latest/meta-data/placement/availability-zone/',
            200,
            b'us-mars-2a',
        )
    ]


def check(name, condition, evidence):
    status = 'PASS' if condition else 'FAIL'
    print(f'[{status}] {name}')
    for line in evidence:
        print(f'       {line}')
    if not condition:
        FAILURES.append(name)


def run_fetcher_scenarios():
    print('== IMDS fetcher behavior matrix (fake transport, no network) ==')
    for endpoint_kind, base_url, extra_config in [
        ('default-endpoint', 'http://169.254.169.254', {}),
        (
            'custom-endpoint',
            CUSTOM_ENDPOINT,
            {'ec2_metadata_service_endpoint': CUSTOM_ENDPOINT},
        ),
    ]:
        for fetcher_kind in ('credentials', 'region'):
            for mode, v1_disabled in [
                ('default(v1-allowed)', False),
                ('enforced(v1-disabled)', True),
            ]:
                for failure_name, outcome in token_failures(base_url).items():
                    _run_one(
                        endpoint_kind,
                        fetcher_kind,
                        mode,
                        v1_disabled,
                        failure_name,
                        outcome,
                        base_url,
                        extra_config,
                    )


def _run_one(
    endpoint_kind,
    fetcher_kind,
    mode,
    v1_disabled,
    failure_name,
    token_outcome,
    base_url,
    extra_config,
):
    config = dict(extra_config)
    if v1_disabled:
        config['ec2_metadata_v1_disabled'] = True
    # Script: token PUT fails, then enough successes for any fallback path.
    if fetcher_kind == 'credentials':
        outcomes = [token_outcome] + _creds_success_outcomes(base_url)
    else:
        outcomes = [token_outcome] + _region_success_outcomes(base_url)
    transport = RecordingTransport(outcomes)

    env = {'AWS_EC2_METADATA_DISABLED': 'false'}
    if fetcher_kind == 'credentials':
        fetcher = InstanceMetadataFetcher(
            num_attempts=1, env=env, config=config
        )
        invoke = fetcher.retrieve_iam_role_credentials
    else:
        fetcher = InstanceMetadataRegionFetcher(
            num_attempts=1, env=env, config=config
        )
        invoke = fetcher.retrieve_region
    fetcher._session.send = transport.send

    raised = None
    try:
        invoke()
    except (MetadataRetrievalError, BadIMDSRequestError) as e:
        raised = type(e).__name__

    name = (
        f'{endpoint_kind} / {fetcher_kind} / {mode} / token-PUT:{failure_name}'
    )
    evidence = transport.describe() or ['(no requests)']
    if raised:
        evidence.append(f'raised: {raised}')
    tokenless = transport.tokenless_gets()

    if v1_disabled:
        # The core contract: a token-endpoint failure must never turn into
        # a tokenless metadata request.
        ok = not tokenless
        if failure_name == 'http-400':
            # 400 is a client error: BadIMDSRequestError, surfaced by the
            # region fetcher, swallowed to {} by the credentials fetcher.
            ok = ok and (
                raised == 'BadIMDSRequestError'
                or (fetcher_kind == 'credentials' and raised is None)
            )
        else:
            ok = ok and raised == 'MetadataRetrievalError'
    else:
        if failure_name == 'http-400':
            # 400 must not fall back to v1 even in default mode.
            ok = not tokenless and (
                raised == 'BadIMDSRequestError'
                or (fetcher_kind == 'credentials' and raised is None)
            )
        else:
            # Documented compatibility fallback: exactly the tokenless GETs.
            ok = raised is None and len(tokenless) >= 1
    check(name, ok, evidence)


def _session_with(env_updates, config_file_text=None, instance_vars=None):
    env = {
        k: v for k, v in os.environ.items() if not k.startswith('AWS_')
    }
    env.update(env_updates)
    if config_file_text is not None:
        import tempfile

        fd, path = tempfile.mkstemp(suffix='.ini')
        with os.fdopen(fd, 'w') as f:
            f.write(config_file_text)
        env['AWS_CONFIG_FILE'] = path
    patcher = mock.patch.dict(os.environ, env, clear=True)
    patcher.start()
    session = botocore.session.Session()
    for key, value in (instance_vars or {}).items():
        session.set_config_variable(key, value)
    return patcher, session


def check_config_precedence():
    print('== Config precedence and entry-point wiring ==')
    profile_true = '[default]\nec2_metadata_v1_disabled = true\n'

    cases = [
        ('default (nothing set)', {}, None, {}, False),
        ('profile sets true', {}, profile_true, {}, True),
        (
            'env=false overrides profile=true',
            {'AWS_EC2_METADATA_V1_DISABLED': 'false'},
            profile_true,
            {},
            False,
        ),
        (
            'env=true alone',
            {'AWS_EC2_METADATA_V1_DISABLED': 'true'},
            None,
            {},
            True,
        ),
        (
            'explicit=true overrides env=false',
            {'AWS_EC2_METADATA_V1_DISABLED': 'false'},
            None,
            {'ec2_metadata_v1_disabled': True},
            True,
        ),
        (
            'explicit=false overrides env=true',
            {'AWS_EC2_METADATA_V1_DISABLED': 'true'},
            None,
            {'ec2_metadata_v1_disabled': False},
            False,
        ),
    ]
    for name, env, profile, instance_vars, expected in cases:
        patcher, session = _session_with(env, profile, instance_vars)
        try:
            resolved = session.get_config_variable('ec2_metadata_v1_disabled')
            check(
                f'precedence: {name} -> {resolved}',
                resolved is expected,
                [f'expected={expected} resolved={resolved}'],
            )
        finally:
            patcher.stop()

    # Both production entry points must wire the resolved value through.
    patcher, session = _session_with(
        {'AWS_EC2_METADATA_V1_DISABLED': 'true'}
    )
    try:
        resolver = create_credential_resolver(session)
        creds_fetcher = resolver.get_provider('iam-role')._role_fetcher
        check(
            'wiring: create_credential_resolver passes v1-disabled to fetcher',
            creds_fetcher._imds_v1_disabled is True,
            [f'fetcher._imds_v1_disabled={creds_fetcher._imds_v1_disabled}'],
        )
        region_fetcher = IMDSRegionProvider(session)._create_fetcher()
        check(
            'wiring: IMDSRegionProvider passes v1-disabled to fetcher',
            region_fetcher._imds_v1_disabled is True,
            [f'fetcher._imds_v1_disabled={region_fetcher._imds_v1_disabled}'],
        )
    finally:
        patcher.stop()

    # End-to-end through the session: enforced mode + token 404 must raise
    # before any tokenless GET leaves the process.
    patcher, session = _session_with(
        {'AWS_EC2_METADATA_V1_DISABLED': 'true'}
    )
    try:
        transport = RecordingTransport(
            [_http_response('http://169.254.169.254/' + TOKEN_PATH, 404)]
        )
        with mock.patch(
            'botocore.httpsession.URLLib3Session.send', transport.send
        ):
            raised = None
            try:
                IMDSRegionProvider(session).provide()
            except MetadataRetrievalError:
                raised = 'MetadataRetrievalError'
        check(
            'end-to-end: region discovery raises, no tokenless GET',
            raised == 'MetadataRetrievalError'
            and not transport.tokenless_gets(),
            transport.describe() + [f'raised: {raised}'],
        )
    finally:
        patcher.stop()


def main():
    print(
        'NOTE: all traffic is intercepted by a recording fake transport; '
        'no metadata endpoint is contacted.\n'
    )
    run_fetcher_scenarios()
    print()
    check_config_precedence()
    print()
    if FAILURES:
        print(f'RESULT: FAIL ({len(FAILURES)} checks failed)')
        for name in FAILURES:
            print(f'  - {name}')
        return 1
    print('RESULT: PASS (all checks passed)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
