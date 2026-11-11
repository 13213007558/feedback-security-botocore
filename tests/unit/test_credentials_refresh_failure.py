# Copyright (c) 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Refresh failure safety for custom temporary credential providers.

These tests verify that a refresh which returns malformed metadata (missing
fields or an unparseable ``expiry_time``) can never leave the credentials used
for signing in a mixed state, e.g. a new access key paired with the previous
secret key or token.  A controllable clock drives the credentials through both
the advisory and mandatory refresh windows, barriers interleave concurrent
signing requests with an in-flight refresh, and assertions are made against the
frozen credential tuple that SigV4 actually signs with rather than against an
individual credential property.
"""

import threading
from datetime import datetime, timedelta

from dateutil.parser import ParserError
from dateutil.tz import tzutc

import botocore.exceptions
from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import ReadOnlyCredentials, RefreshableCredentials
from tests import unittest

ADVISORY_TIMEOUT = 15 * 60
MANDATORY_TIMEOUT = 10 * 60

# Fixed timeline.  The first snapshot expires at t0 + 60 minutes.
T0 = datetime(2026, 11, 11, 12, 0, 0, tzinfo=tzutc())
FIRST_EXPIRY = T0 + timedelta(minutes=60)
ADVISORY_NOW = T0 + timedelta(minutes=46)  # 14 min left: advisory only
MANDATORY_NOW = T0 + timedelta(minutes=52)  # 8 min left: mandatory window
EXPIRED_NOW = T0 + timedelta(minutes=61)  # 1 min past expiry


class ControllableClock:
    def __init__(self, now):
        self._now = now

    def __call__(self):
        return self._now

    def move_to(self, now):
        self._now = now


class ScriptedRefresh:
    """Refresh callable that returns scripted metadata and records calls."""

    def __init__(self, responses):
        self._responses = list(responses)
        self._last_response = self._responses[-1]
        self.calls = 0
        self.entered = threading.Event()
        self.release = threading.Event()

    def __call__(self):
        self.calls += 1
        self.entered.set()
        self.release.wait(timeout=5)
        # Re-checks after the lock is released can trigger another refresh
        # attempt, so a one-shot queue would raise IndexError and mask the
        # behavior under test.  The final scripted response is sticky.
        response = (
            self._responses.pop(0) if self._responses else self._last_response
        )
        if isinstance(response, Exception):
            raise response
        return response


def good_metadata(generation, now):
    return {
        'access_key': f'ak-{generation}',
        'secret_key': f'sk-{generation}',
        'token': f'tok-{generation}',
        'expiry_time': (now + timedelta(hours=1)).isoformat(),
    }


def make_credentials(clock, responses, generation=1):
    refresher = ScriptedRefresh(responses)
    credentials = RefreshableCredentials(
        f'ak-{generation}',
        f'sk-{generation}',
        f'tok-{generation}',
        FIRST_EXPIRY,
        refresher,
        'custom-test',
        time_fetcher=clock,
        advisory_timeout=ADVISORY_TIMEOUT,
        mandatory_timeout=MANDATORY_TIMEOUT,
    )
    return credentials, refresher


def sign(credentials):
    """Sign a request and return the frozen credential tuple actually used."""
    frozen = credentials.get_frozen_credentials()
    auth = S3SigV4Auth(frozen, 's3', 'us-east-1')
    request = AWSRequest(method='GET', url='https://s3.amazonaws.com/')
    auth.add_auth(request)
    return request.headers, frozen


class TestRefreshFailureKeepsFrozenSnapshotConsistent(unittest.TestCase):
    def test_advisory_refresh_raising_keeps_complete_old_snapshot(self):
        clock = ControllableClock(ADVISORY_NOW)
        credentials, refresher = make_credentials(
            clock, [RuntimeError('provider unavailable')]
        )
        refresher.release.set()

        # Advisory failure is swallowed, so the still-valid old snapshot is
        # returned instead of an exception.
        frozen = credentials.get_frozen_credentials()
        self.assertEqual(
            frozen, ReadOnlyCredentials('ak-1', 'sk-1', 'tok-1', None)
        )
        self.assertEqual(refresher.calls, 1)

        headers, _ = sign(credentials)
        self.assertIn('ak-1', headers['Authorization'])
        self.assertEqual(headers['X-Amz-Security-Token'], 'tok-1')

    def test_advisory_missing_fields_does_not_mutate_any_credential(self):
        clock = ControllableClock(ADVISORY_NOW)
        credentials, refresher = make_credentials(
            clock, [{'access_key': 'ak-2'}, {'access_key': 'ak-2'}]
        )
        refresher.release.set()

        with self.assertRaises(botocore.exceptions.CredentialRetrievalError):
            credentials.get_frozen_credentials()

        # Key validation happens before any field is assigned, so neither the
        # frozen snapshot nor the raw fields can mix generations.
        expected = ReadOnlyCredentials('ak-1', 'sk-1', 'tok-1', None)
        self.assertEqual(credentials._frozen_credentials, expected)
        self.assertEqual(credentials._access_key, 'ak-1')
        self.assertEqual(credentials._secret_key, 'sk-1')
        self.assertEqual(credentials._token, 'tok-1')
        self.assertEqual(credentials._expiry_time, FIRST_EXPIRY)

        # The provider is still broken, so signing cannot silently fall back:
        # every retrieval re-attempts the refresh and keeps raising.
        with self.assertRaises(botocore.exceptions.CredentialRetrievalError):
            sign(credentials)

    def test_advisory_bad_expiration_never_mixes_frozen_credentials(self):
        clock = ControllableClock(ADVISORY_NOW)
        bad_metadata = {
            'access_key': 'ak-2',
            'secret_key': 'sk-2',
            'token': 'tok-2',
            'expiry_time': 'not-a-real-date',
        }
        credentials, refresher = make_credentials(clock, [bad_metadata])
        refresher.release.set()

        # The parse error surfaces from _set_from_data, so it is not covered
        # by the advisory window's exception swallowing.
        with self.assertRaises(ParserError):
            credentials.get_frozen_credentials()

        # The raw fields are staged together before the failing parse, but the
        # published frozen snapshot is still the complete first generation.
        self.assertEqual(
            credentials._frozen_credentials,
            ReadOnlyCredentials('ak-1', 'sk-1', 'tok-1', None),
        )
        self.assertEqual(credentials._expiry_time, FIRST_EXPIRY)
        self.assertEqual(
            (
                credentials._access_key,
                credentials._secret_key,
                credentials._token,
            ),
            ('ak-2', 'sk-2', 'tok-2'),
        )

    def test_mandatory_failure_raises_even_though_snapshot_not_expired(self):
        clock = ControllableClock(MANDATORY_NOW)
        for bad_response in (
            RuntimeError('provider unavailable'),
            {'access_key': 'ak-2'},
        ):
            clock.move_to(MANDATORY_NOW)
            credentials, refresher = make_credentials(clock, [bad_response])
            refresher.release.set()

            with self.assertRaises(Exception):
                credentials.get_frozen_credentials()

            # Inside the mandatory window the old but not-yet-expired snapshot
            # must not be handed out: refresh failure is propagated instead.
            self.assertEqual(
                credentials._frozen_credentials,
                ReadOnlyCredentials('ak-1', 'sk-1', 'tok-1', None),
            )

    def test_expired_snapshot_cannot_be_used_after_refresh_failure(self):
        for bad_response in (
            RuntimeError('provider unavailable'),
            {'access_key': 'ak-2'},
            {
                'access_key': 'ak-2',
                'secret_key': 'sk-2',
                'token': 'tok-2',
                'expiry_time': 'not-a-real-date',
            },
        ):
            clock = ControllableClock(EXPIRED_NOW)
            credentials, refresher = make_credentials(clock, [bad_response])
            refresher.release.set()

            with self.assertRaises(Exception):
                credentials.get_frozen_credentials()
            # The stale tuple may remain on the object, but expired
            # credentials can never extend their life via a failed refresh.
            self.assertEqual(
                credentials._frozen_credentials,
                ReadOnlyCredentials('ak-1', 'sk-1', 'tok-1', None),
            )

    def test_recovery_uses_new_snapshot_without_rebuilding_credentials(self):
        clock = ControllableClock(ADVISORY_NOW)
        credentials, refresher = make_credentials(
            clock,
            [
                {'access_key': 'ak-2'},
                good_metadata(2, ADVISORY_NOW),
            ],
        )
        refresher.release.set()

        with self.assertRaises(botocore.exceptions.CredentialRetrievalError):
            credentials.get_frozen_credentials()

        # A subsequent successful refresh on the same object publishes a fully
        # consistent second generation.
        headers, frozen = sign(credentials)
        self.assertEqual(
            frozen, ReadOnlyCredentials('ak-2', 'sk-2', 'tok-2', None)
        )
        self.assertIn('ak-2', headers['Authorization'])
        self.assertEqual(headers['X-Amz-Security-Token'], 'tok-2')
        self.assertEqual(refresher.calls, 2)


class TestConcurrentSigningInterleavedWithRefresh(unittest.TestCase):
    NUM_READERS = 8

    def _start_signing_threads(self, credentials, gate, storage):
        """Start readers that all wait on ``gate`` before signing."""

        def reader():
            gate.wait(timeout=5)
            try:
                _, frozen = sign(credentials)
                storage['results'].append(
                    (frozen.access_key, frozen.secret_key, frozen.token)
                )
            except Exception as error:
                storage['errors'].append(error)

        threads = [
            threading.Thread(target=reader) for _ in range(self.NUM_READERS)
        ]
        for thread in threads:
            thread.start()
        return threads

    def _join(self, threads):
        for thread in threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive(), "reader thread timed out")

    def test_advisory_window_interleaves_signing_with_one_refresh(self):
        clock = ControllableClock(ADVISORY_NOW)
        credentials, refresh = make_credentials(
            clock, [good_metadata(2, ADVISORY_NOW)]
        )
        storage = {'results': [], 'errors': []}
        gate = threading.Event()
        threads = self._start_signing_threads(credentials, gate, storage)

        # One request drives the refresh and blocks inside the provider.
        def leader():
            frozen = credentials.get_frozen_credentials()
            storage['results'].append(
                (frozen.access_key, frozen.secret_key, frozen.token)
            )

        leader_thread = threading.Thread(target=leader)
        leader_thread.start()
        self.assertTrue(refresh.entered.wait(timeout=5))

        # While the refresh is in flight, release the other signers.  Whichever
        # tuple they observe, it must be a complete generation and never a mix
        # of the staged and previously published credentials.
        gate.set()
        refresh.release.set()
        leader_thread.join(timeout=5)
        self.assertFalse(leader_thread.is_alive(), "leader thread timed out")
        self._join(threads)

        self.assertEqual(storage['errors'], [])
        self.assertEqual(len(storage['results']), self.NUM_READERS + 1)
        for access_key, secret_key, token in storage['results']:
            # The three fields must all come from the same generation; an
            # "ak-2" paired with an "sk-1"/"tok-1" would be the mixed state
            # this test exists to rule out.
            generations = (
                access_key.split('-')[1],
                secret_key.split('-')[1],
                token.split('-')[1],
            )
            self.assertEqual(len(set(generations)), 1, storage['results'])
            self.assertIn(access_key, ('ak-1', 'ak-2'))
        self.assertEqual(refresh.calls, 1)

    def test_mandatory_window_failure_propagates_to_every_signer(self):
        clock = ControllableClock(MANDATORY_NOW)
        credentials, refresh = make_credentials(
            clock, [RuntimeError('provider unavailable')]
        )
        storage = {'results': [], 'errors': []}
        gate = threading.Event()
        threads = self._start_signing_threads(credentials, gate, storage)

        # Park one mandatory refresh inside the provider, then release every
        # waiting signer so they pile onto the refresh lock.
        leader_error = []

        def leader():
            try:
                credentials.get_frozen_credentials()
            except Exception as error:
                leader_error.append(error)

        leader_thread = threading.Thread(target=leader)
        leader_thread.start()
        self.assertTrue(refresh.entered.wait(timeout=5))
        gate.set()
        # Give the released signers a chance to block on the lock before the
        # provider raises and unwinds the mandatory refresh.
        refresh.release.set()
        leader_thread.join(timeout=5)
        self.assertFalse(leader_thread.is_alive(), "leader thread timed out")
        self._join(threads)

        self.assertEqual(storage['results'], [])
        self.assertEqual(len(leader_error), 1)
        self.assertIsInstance(leader_error[0], RuntimeError)
        self.assertEqual(len(storage['errors']), self.NUM_READERS)
        for error in storage['errors']:
            self.assertIsInstance(error, RuntimeError)

    def test_mandatory_failure_then_recovery_on_same_credentials(self):
        clock = ControllableClock(MANDATORY_NOW)
        credentials, refresh = make_credentials(
            clock,
            [
                RuntimeError('provider unavailable'),
                good_metadata(2, MANDATORY_NOW),
            ],
        )
        refresh.release.set()

        with self.assertRaises(RuntimeError):
            credentials.get_frozen_credentials()

        # The same credential object refreshes successfully on the next call;
        # neither the object nor the owning session has to be rebuilt.
        headers, frozen = sign(credentials)
        self.assertEqual(
            frozen, ReadOnlyCredentials('ak-2', 'sk-2', 'tok-2', None)
        )
        self.assertIn('ak-2', headers['Authorization'])
        self.assertEqual(headers['X-Amz-Security-Token'], 'tok-2')
        self.assertEqual(refresh.calls, 2)


class TestRefreshRecoveryThroughRealSession(unittest.TestCase):
    """End-to-end recovery driven by the signer on a real botocore session."""

    def _build_client(self, session, refresh_responses, clock):
        from botocore.credentials import CredentialProvider

        refresh = ScriptedRefresh(refresh_responses)
        refresh.release.set()

        class CustomProvider(CredentialProvider):
            METHOD = 'custom-test'
            CANONICAL_NAME = 'custom-test'

            def load(self):
                return RefreshableCredentials(
                    'ak-1',
                    'sk-1',
                    'tok-1',
                    FIRST_EXPIRY,
                    refresh,
                    self.METHOD,
                    time_fetcher=clock,
                    advisory_timeout=ADVISORY_TIMEOUT,
                    mandatory_timeout=MANDATORY_TIMEOUT,
                )

        resolver = session.get_component('credential_provider')
        resolver.providers.insert(0, CustomProvider())
        client = session.create_client('s3', region_name='us-east-1')
        return client, refresh

    def test_requests_resume_after_failure_without_rebuilding_session(self):
        from botocore.session import Session
        from tests import ClientHTTPStubber

        clock = ControllableClock(ADVISORY_NOW)
        session = Session()
        client, refresh = self._build_client(
            session,
            [
                {'access_key': 'ak-2'},
                good_metadata(2, ADVISORY_NOW),
            ],
            clock,
        )

        with ClientHTTPStubber(client) as http_stubber:
            # First call enters the advisory refresh, gets malformed metadata
            # and surfaces the retrieval error before any request is sent.
            with self.assertRaises(
                botocore.exceptions.CredentialRetrievalError
            ):
                client.list_buckets()
            self.assertEqual(http_stubber.requests, [])
            self.assertEqual(refresh.calls, 1)

            # The same client/session retries: the refresh now succeeds and a
            # fully consistent second generation signs the outbound request.
            http_stubber.add_response(body=b'<ListBucketsResult/>')
            client.list_buckets()
            request = http_stubber.requests[0]
            authorization = request.headers['Authorization'].decode('utf-8')
            security_token = request.headers['X-Amz-Security-Token'].decode(
                'utf-8'
            )
            self.assertIn('ak-2', authorization)
            self.assertEqual(security_token, 'tok-2')
            self.assertEqual(refresh.calls, 2)
