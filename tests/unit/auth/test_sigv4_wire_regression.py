# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.

"""End-to-end SigV4 wire regression tests.

The existing SigV4 tests stop at the point where an ``Authorization`` header
(or an ``X-Amz-Signature`` query parameter) is produced. They never compare
the data the signer digested against the bytes that are actually attached to
the final :class:`~botocore.awsrequest.AWSPreparedRequest`, which is what gets
serialized onto the socket.

These tests drive a request the whole way, from an :class:`AWSRequest` through
``add_auth`` and ``prepare``, and then recompute the signature *from the
prepared request* using a small, independent SigV4 implementation built only on
the Python standard library (``hmac``/``hashlib``/``urllib.parse``). The
reference code below deliberately does not import or call any botocore signing
routine, so a match means the on-the-wire request carries exactly the inputs
that the AWS SigV4 algorithm specifies. The reference itself is cross-checked
against the official ``aws4_testsuite`` reference vectors.
"""
import datetime
import hashlib
import hmac
from urllib.parse import quote, urlsplit

import pytest

import botocore.auth
from botocore.auth import (
    S3SigV4Auth,
    S3SigV4QueryAuth,
    SigV4Auth,
    SigV4QueryAuth,
)
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from tests import FreezeTime

# Fixed fake credentials and fixed clock: every signature below is therefore
# deterministic and reproducible without any environment or network access.
ACCESS_KEY = "AKIDEXAMPLE"
SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
SESSION_TOKEN = "AQoDYXdzEBcaoAJfake-token/with+special"
REGION = "us-east-1"
SERVICE = "service"
S3_SERVICE = "s3"
SIGN_DATE = datetime.datetime(2015, 8, 30, 12, 36, 0)
TIMESTAMP = SIGN_DATE.strftime("%Y%m%dT%H%M%SZ")
DATE_STAMP = TIMESTAMP[:8]
EXPIRES = 300

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD"

# Headers the SigV4 spec excludes from signing. Mirrors botocore.auth but is
# duplicated here on purpose so the reference stays fully independent.
UNSIGNED_HEADER_NAMES = {
    "baggage",
    "connection",
    "expect",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "traceparent",
    "tracestate",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "user-agent",
    "x-amzn-trace-id",
}
# Added by AWSRequestPreparer only after signing, so they can never be part of
# the canonical request that was actually signed.
POST_SIGN_HEADER_NAMES = {"content-length", "transfer-encoding"}


# ---------------------------------------------------------------------------
# Independent, stdlib-only SigV4 reference implementation.
# ---------------------------------------------------------------------------
def _hmac_sha256(key, message):
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def reference_signing_key(secret_key, date_stamp, region, service):
    key = _hmac_sha256(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    key = _hmac_sha256(key, region)
    key = _hmac_sha256(key, service)
    return _hmac_sha256(key, "aws4_request")


def _remove_dot_segments(path):
    # RFC 3986 section 5.2.4, plus the AWS requirement that consecutive
    # slashes are collapsed. Reimplemented independently of botocore.utils.
    if not path:
        return ""
    output = []
    for segment in path.split("/"):
        if segment and segment != ".":
            if segment == "..":
                if output:
                    output.pop()
            else:
                output.append(segment)
    prefix = "/" if path.startswith("/") else ""
    suffix = "/" if path.endswith("/") and output else ""
    return prefix + "/".join(output) + suffix


def reference_canonical_path(wire_path, *, is_s3):
    if not wire_path:
        return "/"
    if is_s3:
        # S3 object keys are opaque and must not be normalized or re-encoded.
        return wire_path
    return quote(_remove_dot_segments(wire_path), safe="/-._~")


def reference_canonical_query(wire_query):
    if not wire_query:
        return ""
    pairs = []
    for chunk in wire_query.split("&"):
        name, separator, value = chunk.partition("=")
        # The signature is the output of the process; it is never an input.
        if name == "X-Amz-Signature":
            continue
        pairs.append((name, value) if separator else (name, ""))
    return "&".join(f"{name}={value}" for name, value in sorted(pairs))


def _trim_header_value(value):
    return " ".join(str(value).split())


def reference_canonical_headers(header_pairs, host):
    collected = {}
    for name, value in header_pairs:
        lowered = name.lower()
        if (
            lowered == "authorization"
            or lowered in UNSIGNED_HEADER_NAMES
            or lowered in POST_SIGN_HEADER_NAMES
        ):
            continue
        collected.setdefault(lowered, []).append(_trim_header_value(value))
    collected.setdefault("host", [host])
    lines = [
        f"{name}:{','.join(collected[name])}" for name in sorted(collected)
    ]
    canonical_headers = "\n".join(lines) + "\n"
    signed_headers = ";".join(sorted(collected))
    return canonical_headers, signed_headers


def reference_payload_hash(prepared, *, unsigned):
    explicit = None
    for name, value in prepared.headers.items():
        if name.lower() == "x-amz-content-sha256":
            explicit = str(value)
    if unsigned or explicit == UNSIGNED_PAYLOAD:
        return UNSIGNED_PAYLOAD
    if explicit is not None:
        return explicit
    body = prepared.body or b""
    if isinstance(body, str):
        body = body.encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def reference_signature(
    prepared,
    credentials,
    *,
    service,
    region,
    timestamp,
    is_s3=False,
    unsigned_payload=False,
    presigned=False,
):
    """Recompute the SigV4 signature strictly from the prepared request."""
    parts = urlsplit(prepared.url)
    host = parts.hostname or ""
    default_ports = {"http": 80, "https": 443}
    if parts.port and parts.port != default_ports.get(parts.scheme):
        host = f"{host}:{parts.port}"

    canonical_headers, signed_headers = reference_canonical_headers(
        list(prepared.headers.items()), host
    )
    canonical_request = "\n".join(
        [
            prepared.method.upper(),
            reference_canonical_path(parts.path, is_s3=is_s3),
            reference_canonical_query(parts.query),
            canonical_headers,
            signed_headers,
            reference_payload_hash(prepared, unsigned=unsigned_payload),
        ]
    )
    scope = f"{timestamp[:8]}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            timestamp,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signing_key = reference_signing_key(
        credentials.secret_key, timestamp[:8], region, service
    )
    signature = hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return signature, canonical_request, string_to_sign


# A small, fixed reference vector using the same key material and clock as the
# official aws4_testsuite "get-vanilla" case. Its expected signature is taken
# verbatim from that shipped vector, so the stdlib reference below can be
# checked against a known-good value without reusing any botocore signing code.
REFERENCE_VECTOR = {
    "method": "GET",
    "url": "https://example.amazonaws.com/",
    "service": "service",
    "region": "us-east-1",
    "expected_signature": (
        "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    ),
    "empty_payload_hash": EMPTY_SHA256,
}


def make_credentials(with_token=True):
    token = SESSION_TOKEN if with_token else None
    return Credentials(ACCESS_KEY, SECRET_KEY, token)


def sign(auth_class, request, service, *, expires=None):
    kwargs = {}
    if expires is not None:
        kwargs["expires"] = expires
    auth = auth_class(make_credentials(), service, REGION, **kwargs)
    with FreezeTime(module=botocore.auth.datetime, date=SIGN_DATE):
        auth.add_auth(request)
    return auth, request.prepare()


def assert_wire_signature_matches(
    prepared, credentials, *, service, is_s3=False, unsigned_payload=False
):
    expected = prepared.headers["Authorization"].rsplit("Signature=", 1)[1]
    actual, canonical_request, string_to_sign = reference_signature(
        prepared,
        credentials,
        service=service,
        region=REGION,
        timestamp=TIMESTAMP,
        is_s3=is_s3,
        unsigned_payload=unsigned_payload,
    )
    assert actual == expected, (
        f"Signature recomputed from the prepared request ({actual}) does "
        f"not match the Authorization header ({expected}).\n"
        f"Canonical request rebuilt from the wire request:\n"
        f"{canonical_request}\nString to sign:\n{string_to_sign}"
    )


def assert_presigned_signature_matches(
    prepared, credentials, *, service, is_s3=False
):
    query = urlsplit(prepared.url).query
    wire_signature = dict(
        chunk.split("=", 1) for chunk in query.split("&") if "=" in chunk
    )["X-Amz-Signature"]
    # S3 presigners always use the literal UNSIGNED-PAYLOAD; the generic
    # query signer hashes the (empty) body like the header signer does.
    actual, canonical_request, string_to_sign = reference_signature(
        prepared,
        credentials,
        service=service,
        region=REGION,
        timestamp=TIMESTAMP,
        is_s3=is_s3,
        unsigned_payload=is_s3,
        presigned=True,
    )
    assert actual == wire_signature, (
        f"Presigned signature recomputed from the prepared URL ({actual}) "
        f"does not match X-Amz-Signature ({wire_signature}).\n"
        f"Canonical request rebuilt from the wire URL:\n{canonical_request}"
        f"\nString to sign:\n{string_to_sign}"
    )


# ---------------------------------------------------------------------------
# Sanity checks for the independent reference implementation itself.
# ---------------------------------------------------------------------------
class TestReferenceImplementation:
    def test_signing_key_is_derived_raw_bytes(self):
        # The SigV4 derived key is the HMAC chain ending in aws4_request,
        # which always yields a 32-byte SHA-256 digest.
        key = reference_signing_key(
            SECRET_KEY, DATE_STAMP, REGION, SERVICE
        )
        assert len(key) == 32

    def test_reference_reproduces_known_get_vanilla_vector(self):
        # End-to-end anchor against the official aws4_testsuite "get-vanilla"
        # signature, computed here purely from the stdlib reference and the
        # prepared request, with no botocore signing routine involved.
        credentials = make_credentials(with_token=False)
        request = AWSRequest(
            method=REFERENCE_VECTOR["method"],
            url=REFERENCE_VECTOR["url"],
        )
        auth = SigV4Auth(credentials, SERVICE, REGION)
        with FreezeTime(module=botocore.auth.datetime, date=SIGN_DATE):
            auth.add_auth(request)
        prepared = request.prepare()
        actual, _, _ = reference_signature(
            prepared,
            credentials,
            service=REFERENCE_VECTOR["service"],
            region=REFERENCE_VECTOR["region"],
            timestamp=TIMESTAMP,
        )
        assert actual == REFERENCE_VECTOR["expected_signature"]
        # And the library must land on that same independently known value.
        assert (
            prepared.headers["Authorization"].rsplit("Signature=", 1)[1]
            == REFERENCE_VECTOR["expected_signature"]
        )

    def test_reference_agrees_with_library_on_plain_request(self):
        # Cross-validate the stdlib reference against botocore on the simplest
        # possible request, exercising both implementations end to end.
        request = AWSRequest(
            method="GET", url="https://example.amazonaws.com/"
        )
        _, prepared = sign(SigV4Auth, request, SERVICE)
        assert_wire_signature_matches(
            prepared, make_credentials(), service=SERVICE
        )

    def test_canonical_path_rules_are_independent(self):
        assert (
            reference_canonical_path("/a//b///c", is_s3=False) == "/a/b/c"
        )
        assert reference_canonical_path("/a//b///c", is_s3=True) == (
            "/a//b///c"
        )
        assert reference_canonical_path("/obj%2Fkey", is_s3=False) == (
            "/obj%252Fkey"
        )
        assert reference_canonical_path("/obj%2Fkey", is_s3=True) == (
            "/obj%2Fkey"
        )


# ---------------------------------------------------------------------------
# Query string handling.
# ---------------------------------------------------------------------------
class TestWireQueryString:
    def test_duplicate_query_keys_and_empty_value(self):
        request = AWSRequest(
            method="GET",
            url="https://example.amazonaws.com/",
            params=[
                ("key", "val1"),
                ("key", "val2"),
                ("blank", ""),
            ],
        )
        _, prepared = sign(SigV4Auth, request, SERVICE)
        # Both repeated keys and the blank value survive onto the wire.
        assert "key=val1&key=val2" in prepared.url
        assert "blank=" in prepared.url
        assert_wire_signature_matches(
            prepared, make_credentials(), service=SERVICE
        )

    def test_plus_space_and_percent_in_params(self):
        request = AWSRequest(
            method="GET",
            url="https://example.amazonaws.com/path",
            params={"q": "a+b c%20d"},
        )
        _, prepared = sign(SigV4Auth, request, SERVICE)
        # The prepared query must use the same encoding as the canonical
        # query: spaces become %20 (never '+'), '%' becomes %25, and an
        # existing '+' is preserved as %2B.
        assert "q=a%2Bb%20c%2520d" in prepared.url
        assert "+" not in urlsplit(prepared.url).query
        assert_wire_signature_matches(
            prepared, make_credentials(), service=SERVICE
        )

    def test_raw_url_query_plus_and_percent(self):
        # Query strings already present in the URL are treated as pre-encoded
        # and must pass through byte-for-byte in both the wire request and
        # the canonical query.
        url = "https://example.amazonaws.com/p?x=a%2Bb&y=100%25"
        request = AWSRequest(method="GET", url=url)
        _, prepared = sign(SigV4Auth, request, SERVICE)
        assert prepared.url == url
        assert_wire_signature_matches(
            prepared, make_credentials(), service=SERVICE
        )

    def test_list_value_params_expand_and_match_signature(self):
        request = AWSRequest(
            method="GET",
            url="https://example.amazonaws.com/",
            params={"key": ["a", "b"]},
        )
        _, prepared = sign(SigV4Auth, request, SERVICE)
        assert "key=a&key=b" in prepared.url
        assert_wire_signature_matches(
            prepared, make_credentials(), service=SERVICE
        )


# ---------------------------------------------------------------------------
# Path handling: generic service vs S3 divergence.
# ---------------------------------------------------------------------------
class TestWirePathNormalization:
    @pytest.mark.parametrize(
        "auth_class,service,is_s3",
        [
            (SigV4Auth, SERVICE, False),
            (S3SigV4Auth, S3_SERVICE, True),
        ],
    )
    def test_encoded_slash_differs_between_generic_and_s3(
        self, auth_class, service, is_s3
    ):
        url = (
            f"https://example.amazonaws.com/bucket/obj%2Fkey"
            if not is_s3
            else "https://s3.amazonaws.com/bucket/obj%2Fkey"
        )
        request = AWSRequest(method="GET", url=url)
        _, prepared = sign(auth_class, request, service)
        # The wire path is untouched in both cases.
        assert urlsplit(prepared.url).path == "/bucket/obj%2Fkey"
        assert_wire_signature_matches(
            prepared,
            make_credentials(),
            service=service,
            is_s3=is_s3,
        )

    @pytest.mark.parametrize(
        "auth_class,service,is_s3",
        [
            (SigV4Auth, SERVICE, False),
            (S3SigV4Auth, S3_SERVICE, True),
        ],
    )
    def test_duplicate_path_separators(self, auth_class, service, is_s3):
        url = (
            "https://example.amazonaws.com/a//b///c"
            if not is_s3
            else "https://s3.amazonaws.com/bucket/a//b///c"
        )
        request = AWSRequest(method="GET", url=url)
        _, prepared = sign(auth_class, request, service)
        # S3 keeps consecutive slashes on the wire; the generic signer also
        # leaves the URL alone but normalizes them only inside the canonical
        # request. Either way the wire request must verify against its own
        # signature.
        assert urlsplit(prepared.url).path == url.split(".com")[1]
        assert_wire_signature_matches(
            prepared,
            make_credentials(),
            service=service,
            is_s3=is_s3,
        )

    def test_generic_and_s3_produce_distinct_canonical_paths(self):
        # Same logical input, two services: prove the canonical paths differ.
        path = "/bucket/obj%2Fkey"
        generic = AWSRequest(
            method="GET", url="https://example.amazonaws.com" + path
        )
        s3 = AWSRequest(method="GET", url="https://s3.amazonaws.com" + path)
        _, generic_prepared = sign(SigV4Auth, generic, SERVICE)
        _, s3_prepared = sign(S3SigV4Auth, s3, S3_SERVICE)
        generic_sig = generic_prepared.headers["Authorization"].rsplit(
            "Signature=", 1
        )[1]
        s3_sig = s3_prepared.headers["Authorization"].rsplit(
            "Signature=", 1
        )[1]
        assert generic_sig != s3_sig
        assert (
            reference_canonical_path(
                urlsplit(generic_prepared.url).path, is_s3=False
            )
            == "/bucket/obj%252Fkey"
        )
        assert (
            reference_canonical_path(
                urlsplit(s3_prepared.url).path, is_s3=True
            )
            == "/bucket/obj%2Fkey"
        )


# ---------------------------------------------------------------------------
# Header handling, including repeated header values.
# ---------------------------------------------------------------------------
class TestWireHeaders:
    def test_repeated_header_values_signed_and_sent(self):
        request = AWSRequest(
            method="GET", url="https://example.amazonaws.com/"
        )
        request.headers["X-Multi"] = "one"
        request.headers["X-Multi"] = "two"
        _, prepared = sign(SigV4Auth, request, SERVICE)
        # Both values must be present on the prepared request and must match
        # the comma-joined value that was folded into the canonical header.
        assert prepared.headers.get_all("x-multi") == ["one", "two"]
        assert "x-multi" in prepared.headers["Authorization"]
        assert_wire_signature_matches(
            prepared, make_credentials(), service=SERVICE
        )

    def test_header_value_whitespace_trimmed_like_canonical_form(self):
        request = AWSRequest(
            method="GET", url="https://example.amazonaws.com/"
        )
        request.headers["X-Spaced"] = "  multiple   spaces  "
        _, prepared = sign(SigV4Auth, request, SERVICE)
        assert_wire_signature_matches(
            prepared, make_credentials(), service=SERVICE
        )

    def test_session_token_header_is_on_the_wire_and_signed(self):
        request = AWSRequest(
            method="GET", url="https://example.amazonaws.com/"
        )
        _, prepared = sign(SigV4Auth, request, SERVICE)
        assert (
            prepared.headers["X-Amz-Security-Token"] == SESSION_TOKEN
        )
        assert "x-amz-security-token" in prepared.headers["Authorization"]
        assert_wire_signature_matches(
            prepared, make_credentials(), service=SERVICE
        )

    def test_request_without_session_token(self):
        request = AWSRequest(
            method="GET", url="https://example.amazonaws.com/"
        )
        credentials = make_credentials(with_token=False)
        auth = SigV4Auth(credentials, SERVICE, REGION)
        with FreezeTime(module=botocore.auth.datetime, date=SIGN_DATE):
            auth.add_auth(request)
        prepared = request.prepare()
        assert "X-Amz-Security-Token" not in prepared.headers
        assert_wire_signature_matches(
            prepared, credentials, service=SERVICE
        )


# ---------------------------------------------------------------------------
# Payload handling, including S3 UNSIGNED-PAYLOAD.
# ---------------------------------------------------------------------------
class _SeekableEmptyStream:
    def read(self, size=-1):
        return b""

    def seek(self, *args):
        pass

    def tell(self):
        return 0


class TestWirePayload:
    def test_signed_body_hash_matches_prepared_body(self):
        body = b"object-bytes"
        request = AWSRequest(
            method="PUT",
            url="https://example.amazonaws.com/key",
            data=body,
        )
        _, prepared = sign(SigV4Auth, request, SERVICE)
        assert prepared.body == body
        assert_wire_signature_matches(
            prepared, make_credentials(), service=SERVICE
        )

    def test_s3_unsigned_payload_header_is_signed(self):
        request = AWSRequest(
            method="PUT",
            url="https://s3.amazonaws.com/bucket/key",
            data=_SeekableEmptyStream(),
            headers={"Content-MD5": "fake-md5"},
        )
        # Streaming input plus a checksum header over HTTPS is the S3
        # condition that selects UNSIGNED-PAYLOAD.
        request.context["has_streaming_input"] = True
        _, prepared = sign(S3SigV4Auth, request, S3_SERVICE)
        assert (
            prepared.headers["X-Amz-Content-SHA256"] == UNSIGNED_PAYLOAD
        )
        assert_wire_signature_matches(
            prepared,
            make_credentials(),
            service=S3_SERVICE,
            is_s3=True,
            unsigned_payload=True,
        )


# ---------------------------------------------------------------------------
# Presigned URLs.
# ---------------------------------------------------------------------------
class TestWirePresignedUrl:
    def test_generic_presign_query_params_and_token(self):
        request = AWSRequest(
            method="GET",
            url="https://example.amazonaws.com/resource",
            params={"filter": "a b%20c"},
        )
        _, prepared = sign(
            SigV4QueryAuth, request, SERVICE, expires=EXPIRES
        )
        query = urlsplit(prepared.url).query
        assert "X-Amz-Security-Token=" in query
        assert f"X-Amz-Expires={EXPIRES}" in query
        assert "filter=a%20b%2520c" in query
        assert_presigned_signature_matches(
            prepared, make_credentials(), service=SERVICE
        )

    def test_s3_presign_keeps_encoded_slash(self):
        request = AWSRequest(
            method="GET",
            url="https://s3.amazonaws.com/bucket/obj%2Fkey",
        )
        _, prepared = sign(
            S3SigV4QueryAuth, request, S3_SERVICE, expires=EXPIRES
        )
        assert "/bucket/obj%2Fkey?" in prepared.url
        assert_presigned_signature_matches(
            prepared, make_credentials(), service=S3_SERVICE, is_s3=True
        )

    def test_s3_presign_preserves_raw_query_encoding(self):
        request = AWSRequest(
            method="GET",
            url=(
                "https://s3.amazonaws.com/bucket/key"
                "?x=a%2Bb&y=100%25"
            ),
        )
        _, prepared = sign(
            S3SigV4QueryAuth, request, S3_SERVICE, expires=EXPIRES
        )
        assert "x=a%2Bb&y=100%25" in prepared.url
        assert_presigned_signature_matches(
            prepared, make_credentials(), service=S3_SERVICE, is_s3=True
        )

    def test_presign_duplicate_query_keys_collapse_is_known_limitation(self):
        # The query-param presigners rebuild the query through parse_qs(),
        # which cannot represent repeated keys, so only one value reaches the
        # wire. This test pins that behavior and verifies that the surviving
        # (single) request is still internally consistent: the signature must
        # still verify against exactly what the prepared URL carries.
        request = AWSRequest(
            method="GET",
            url="https://example.amazonaws.com/resource",
            params=[("key", "val1"), ("key", "val2")],
        )
        _, prepared = sign(
            SigV4QueryAuth, request, SERVICE, expires=EXPIRES
        )
        query = urlsplit(prepared.url).query
        assert query.count("key=") == 1
        assert "key=val2" in query
        assert "val1" not in query
        assert_presigned_signature_matches(
            prepared, make_credentials(), service=SERVICE
        )
