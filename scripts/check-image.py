#!/usr/bin/env python3
"""Check the packaged image using only temporary containers and named volumes."""
import argparse
import json
import os
import secrets
import subprocess
import time
import urllib.error
import urllib.request


def docker(*args):
    return subprocess.check_output(['docker', *args], text=True).strip()


def get(url):
    with urllib.request.urlopen(url, timeout=2) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    assert docker('run', '--rm', args.image, '--version') == args.version
    name = 'nox-auth-check-' + secrets.token_hex(6)
    volumes = [name + suffix for suffix in ('-data', '-local', '-admin')]
    secret = secrets.token_urlsafe(32)
    key = None
    try:
        for volume in volumes:
            docker('volume', 'create', volume)
        for attempt in range(2):
            docker('run', '-d', '--name', name, '-p', '127.0.0.1::8080',
                   '-e', 'NOX_AUTH_PUBLIC_URL=https://auth.example.test',
                   '-e', 'NOX_AUTH_GOOGLE_CLIENT_ID=image-check',
                   '-e', f'NOX_AUTH_GOOGLE_CLIENT_SECRET={secret}',
                   '-e', 'NOX_AUTH_ALLOWED_EMAILS=test@example.test',
                   '-v', volumes[0] + ':/data', '-v', volumes[1] + ':/run/nox-suite',
                   '-v', volumes[2] + ':/run/nox-auth-admin', args.image)
            info = json.loads(docker('inspect', name))[0]
            assert info['Config']['User'] not in ('', '0', 'root')
            port = info['NetworkSettings']['Ports']['8080/tcp'][0]['HostPort']
            origin = 'http://127.0.0.1:' + port
            for _ in range(200):
                try:
                    assert get(origin + '/healthz')['status'] == 'ok'
                    break
                except (OSError, AssertionError):
                    time.sleep(0.1)
            else:
                raise AssertionError('Image failed readiness')
            docker('exec', name, '/usr/local/bin/nox-auth', '--healthcheck')
            docker('exec', name, 'test', '-s', '/etc/ssl/certs/ca-certificates.crt')
            current = get(origin + '/keys')['keys']
            assert all('d' not in item for item in current)
            if key is not None:
                assert current == key, 'Image recreation lost identity'
            key = current
            for path in ('/oauth/token', '/oauth/introspect', '/v1/admission', '/v1/logout', '/v1/clients/app'):
                try:
                    get(origin + path)
                except urllib.error.HTTPError as error:
                    assert error.code >= 400
                else:
                    raise AssertionError('Public image exposed private operation')
            docker('stop', '--time', '12', name)
            assert docker('inspect', '--format', '{{.State.ExitCode}}', name) == '0'
            assert secret not in docker('logs', name)
            docker('rm', name)
        env = {**os.environ, 'NOX_AUTH_PUBLIC_URL': 'https://auth.example.test',
               'NOX_AUTH_GOOGLE_CLIENT_ID': 'compose-check',
               'NOX_AUTH_GOOGLE_CLIENT_SECRET': secret,
               'NOX_AUTH_ALLOWED_EMAILS': 'test@example.test'}
        for files in (['docker-compose.yml'], ['docker-compose.yml', 'docker-compose.dev.yml']):
            command = ['docker', 'compose']
            for file in files:
                command += ['-f', file]
            subprocess.run(command + ['config', '--quiet'], env=env, check=True)
        print('Image non-root startup, CA bundle, Unix healthcheck, recreation and Compose: OK')
    finally:
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for volume in volumes:
            subprocess.run(['docker', 'volume', 'rm', volume], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
