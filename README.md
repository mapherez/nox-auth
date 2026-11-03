# NoX Auth

Headless Google-backed **NoX Login** for NoX applications. One service owns Google credentials, allowed accounts and shared login sessions. Applications retain their frontends and data; Auth has no dashboard.

The service is implemented in Go with SQLite persistence and the ZITADEL OIDC library. The Go client is available in this repository as `github.com/mapherez/nox-auth/client`. No module/image release is implied by the source tree. Application adapters, starting with Yard, are separate work; current product releases do not gain NoX Login merely by starting this container.

## Container setup

Use [docker-compose.yml](docker-compose.yml) in Yard and provide these **four** environment values, using [.env.example](.env.example):

```dotenv
NOX_AUTH_PUBLIC_URL=https://auth.example.com
NOX_AUTH_GOOGLE_CLIENT_ID=your-google-client-id
NOX_AUTH_GOOGLE_CLIENT_SECRET=your-google-client-secret
NOX_AUTH_ALLOWED_EMAILS=you@example.com,another@example.com
```

`auth.example.com` is a placeholder for your Auth HTTPS origin. Configure your existing proxy/tunnel to forward it to the published Auth port, **5712 by default**, using HTTP to the container. Change `NOX_AUTH_PORT` if that host port is already occupied. Only Auth needs this HTTPS Google callback; apps may keep their private HTTP hostname/IP addresses.

In Google Console, register a web application with this exact authorized redirect URI:

```text
https://auth.example.com/auth/google/callback
```

Use your actual configured Auth origin. Do not register every product's internal callback with Google. Configure Google's consent/test-user access as appropriate for your Google project; Auth additionally enforces `NOX_AUTH_ALLOWED_EMAILS`.

The service generates its own signing/encryption material. No JWT secret, certificate files or per-app Google credentials need to be entered. Keep the `nox-auth-data` volume when updating/recreating the container: it contains keys, identities, sessions and registered clients. Back it up as confidential data.

After an image is published, the production Compose can pull it normally. For a local source build:

```sh
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

Compose reads `.env`; the Go binary itself reads process environment, not an implicit `.env` file. Never commit your real `.env`.

## Local channels and application enrollment

Compose creates local Docker volumes automatically; it does not create configuration folders on your Mac:

| Volume | Access and purpose |
| --- | --- |
| `nox-auth-data` | Auth only; persistent private database and key material |
| `nox-suite-local` | Same-host application transport; `nox-auth.sock` accepts authenticated token/session requests |
| `nox-auth-admin` | Auth plus explicitly authorized setup controllers only; `control.sock` registers/updates/removes login clients |

**The admin volume is an administrative capability. Do not mount it in every product, expose it through a proxy, or publish a TCP registration endpoint.** Runtime apps use the shared local volume plus their own client credentials. Merely sharing the ordinary Suite socket directory does not allow an app to register itself or change another client's settings.

A future setup controller creates/persists each app's generated client secret, registers its exact callbacks through the admin socket, and delivers credentials to that application's protected configuration. This repository supplies the service API and Go helper; the corresponding Yard/Backend setup adapters are not implemented here. There is no instruction to copy client JSON or Google secrets between products manually. Auth registration does not change Backend deployment permissions or grant a Yard service administrative authority.

Protocol routes, examples and adapter requirements are in [the NoX Login integration profile](docs/integration.md). Its administrative operations are available only over the separate socket, authenticated by possession of that deliberately restricted filesystem mount. Mounting that capability is an explicit host-administration decision, not human SSO authentication.

## Sessions and account management

- Login sessions last one year, renewable with use. Entering another application with the same browser reuses Auth login; another browser/device has its own session.
- Apps revalidate current admission against local Auth at most every **five minutes while active**, without another Google login. They cannot continue using an expired confirmation if Auth is unavailable. No background polling is needed for idle apps.
- Removing an email and applying the environment configuration blocks new login immediately and invalidates existing Auth sessions. Apps' previously cached confirmations expire within five minutes. Re-adding the email does not restore those old sessions.
- Applying `.env` changes requires recreating the container with the updated environment; `docker restart` alone does not replace its environment. Keep the data volume.
- Local **Sair** ends the current app session. **Sair de todas** will be exposed by Backend's dashboard, and later Portal, using Auth's restricted Suite-logout operation. It revokes the current Auth session and its derived app sessions, not other devices' independent sessions, Google login or Discord linkage.

Each app must keep Auth tokens on its server and use its own protected browser session cookie. The adapter must also periodically revisit Auth through the browser to renew the Auth cookie while it is valid; the Go helper marks this at 30 days. That redirect reuses Auth login and does not require another Google account selection.

## Development and verification

Requires Go **1.26.0+**; release tooling also uses Node and Python 3. Container checks require Docker.

```sh
npm run check
docker build --build-arg VERSION=local-validation -t nox-auth:local-validation .
python3 scripts/check-image.py --image nox-auth:local-validation --version local-validation
```

Tests use disposable state and controlled Google/JWKS fixtures. They cover the real OIDC code flow and cryptographic Google ID-token validation, without real credentials or requests to Google. The image check removes its temporary containers/volumes. Docker may flag the non-secret `NOX_AUTH_*` directory/listen variables as possible secrets because of the word `AUTH`; no Google secret is built into the image.

`/healthz` and `/readyz` report local storage health, not successful Google authentication or a product's integration state. `/.well-known/openid-configuration` and `/keys` expose provider metadata/public keys. `/` returns service information rather than a login dashboard.

Local verification on November 3, 2026 passed on macOS with Go `1.27.3` and minimum Go `1.26.0`: dependency/format/vet/race checks, the security/session suite, five release-tooling tests, actual binary startup/restart, Linux `amd64`/`arm64` cross-builds and workflow validation with `actionlint 1.7.7`. The actual Linux arm64 Docker image passed non-root startup, CA bundle, private healthcheck, data-volume recreation and Compose checks. Linux amd64 was cross-compiled, not runtime-tested locally. Real Google credentials, GitHub CI, image publication and installed Yard integration were not exercised by these local checks.

CI checks formatting, dependency locks, vet, race tests, binary startup/restart, minimum/current Go, macOS, Linux cross-builds and the actual container. Release publication is gated on CI. `npm run release` is an explicit operator action that validates, commits the selected version, tags and pushes; it requires an existing committed repository/remote. No release has been created by implementing this repository.

## Scope and references

- [NoX Login requirements contract](NOX_AUTH_CONTRACT.md)
- [Implemented integration profile](docs/integration.md)
- [Security boundary](SECURITY.md)
- Suite plan: `Documents/NOX_SUITE_IMPLEMENTATION_PLAN.md` in `nox-mcp`

Auth does not adapt existing product login screens, complete Yard registration/lifecycle, alter MCP permissions, implement the CLI or provide a Portal. Yard login adaptation and installed acceptance come next, preserving its data and rollback path.

Licensed under [CC BY-NC-SA 4.0](LICENSE). Dependency licenses remain their respective authors' licenses.
