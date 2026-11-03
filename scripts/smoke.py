#!/usr/bin/env python3
"""Run the real binary with disposable state; never contact Google."""
import argparse
import json
import os
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def get(url):
    with urllib.request.urlopen(url, timeout=2) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    subprocess.run([binary, '--version'], check=True)
    with tempfile.TemporaryDirectory(prefix='na') as directory:
        base = Path(directory)
        secret = secrets.token_urlsafe(32)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        env = {**os.environ, 'NOX_AUTH_PUBLIC_URL': 'https://auth.example.test',
               'NOX_AUTH_GOOGLE_CLIENT_ID': 'smoke-client',
               'NOX_AUTH_GOOGLE_CLIENT_SECRET': secret,
               'NOX_AUTH_ALLOWED_EMAILS': 'test@example.test',
               'NOX_AUTH_LISTEN_ADDR': f'127.0.0.1:{port}',
               'NOX_AUTH_DATA_DIR': str(base / 'data'),
               'NOX_AUTH_SUITE_SOCKET_DIR': str(base / 's'),
               'NOX_AUTH_ADMIN_SOCKET_DIR': str(base / 'a')}
        key = None
        for attempt in range(2):
            proc = subprocess.Popen([binary], env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True)
            try:
                origin = f'http://127.0.0.1:{port}'
                for _ in range(100):
                    if proc.poll() is not None:
                        raise AssertionError('Auth exited before readiness')
                    try:
                        assert get(origin + '/healthz')['status'] == 'ok'
                        break
                    except (OSError, AssertionError):
                        time.sleep(0.1)
                else:
                    raise AssertionError('Auth did not become ready')
                assert get(origin + '/')['dashboard'] is False
                metadata = get(origin + '/.well-known/openid-configuration')
                assert metadata['issuer'] == env['NOX_AUTH_PUBLIC_URL']
                keys = get(origin + '/keys')['keys']
                assert len(keys) == 1 and 'd' not in keys[0]
                if key is not None:
                    assert key == keys, 'Keys changed after restart'
                key = keys
                for path in ('/oauth/token', '/oauth/introspect', '/v1/admission', '/v1/clients/x', '/v1/logout'):
                    try:
                        get(origin + path)
                    except urllib.error.HTTPError as error:
                        assert error.code >= 400
                    else:
                        raise AssertionError('Private route exposed publicly')
                subprocess.run([binary, '--healthcheck'], env=env, check=True)
            finally:
                proc.terminate()
                try:
                    output, _ = proc.communicate(timeout=12)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    output, _ = proc.communicate()
                    raise AssertionError('Auth did not shut down gracefully')
                assert secret not in output, 'Secret in process logs'
                if proc.returncode != 0:
                    raise AssertionError(f'Auth failed: {output}')
    print('Binary startup, private boundary, persistent keys and graceful restart: OK')


if __name__ == '__main__':
    main()
