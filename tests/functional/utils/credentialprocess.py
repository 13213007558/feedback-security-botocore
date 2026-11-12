# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""This is a dummy implementation of a credential provider process."""

import argparse
import json
import sys
import threading
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--raise-error',
        action='store_true',
        help=(
            'If set, this will cause the process to return a non-zero exit code '
            'and print to stderr.'
        ),
    )
    parser.add_argument(
        '--sleep',
        type=float,
        default=0,
        help='Sleep for this many seconds before printing credentials.',
    )
    parser.add_argument(
        '--stdout-bytes',
        type=int,
        default=0,
        help='Print this many extra bytes to stdout after the credentials.',
    )
    parser.add_argument(
        '--stderr-bytes',
        type=int,
        default=0,
        help='Print this many bytes to stderr before the credentials.',
    )
    parser.add_argument(
        '--noisy-stderr-bytes',
        type=int,
        default=0,
        help=(
            'Write this many bytes to stderr from a background thread while '
            'stdout is produced so both pipes are written concurrently.'
        ),
    )
    parser.add_argument(
        '--invalid-json',
        action='store_true',
        help='Print output that is not valid JSON.',
    )
    parser.add_argument(
        '--expiration-past',
        action='store_true',
        help='Emit credentials whose expiration is already in the past.',
    )
    parser.add_argument(
        '--fail-then-succeed',
        action='store_true',
        help=(
            'Exit non-zero on the first invocation and print credentials on '
            'subsequent invocations.'
        ),
    )
    args = parser.parse_args()
    if args.raise_error:
        raise Exception('Failed to fetch credentials.')
    if args.fail_then_succeed:
        marker = 'credentialprocess-fail-then-succeed'
        try:
            with open(marker) as handle:
                attempts = int(handle.read().strip() or '0')
        except OSError:
            attempts = 0
        attempts += 1
        with open(marker, 'w') as handle:
            handle.write(str(attempts))
        if attempts == 1:
            sys.stderr.write('temporary credential failure\n')
            sys.exit(1)
    if args.sleep:
        time.sleep(args.sleep)
    if args.noisy_stderr_bytes:
        # Stream a large amount of stderr from a separate thread while the
        # main thread prepares stdout.  Both pipes therefore carry data at
        # the same time and have to be drained concurrently.
        def write_noisy_stderr():
            remaining = args.noisy_stderr_bytes
            while remaining > 0:
                chunk = 'e' * min(4096, remaining)
                sys.stderr.write(chunk)
                sys.stderr.flush()
                remaining -= len(chunk)

        writer = threading.Thread(target=write_noisy_stderr)
        writer.start()
        # Give the writer a head start so the stderr pipe is likely already
        # filling before stdout emits anything.
        time.sleep(0.05)
    else:
        writer = None
    if args.stderr_bytes:
        sys.stderr.write('e' * args.stderr_bytes)
        sys.stderr.flush()
    if args.invalid_json:
        sys.stdout.write('this is not json')
        sys.stdout.flush()
        if writer is not None:
            writer.join()
        return
    payload = {
        'AccessKeyId': 'spam',
        'SecretAccessKey': 'eggs',
        'Version': 1,
    }
    if args.expiration_past:
        payload['Expiration'] = '2000-01-01T00:00:00Z'
    print(json.dumps(payload))
    sys.stdout.flush()
    if writer is not None:
        writer.join()
    if args.stdout_bytes:
        # Extra bytes after the JSON keep stdout under the size budget while
        # ensuring both streams are being written at the same time.  A
        # leading newline keeps the leading payload valid JSON.
        sys.stdout.write('\n' + ('x' * args.stdout_bytes))
        sys.stdout.flush()


if __name__ == "__main__":
    main()
