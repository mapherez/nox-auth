# Changelog

Tagged source changes. Published artifacts are recorded in [GitHub Releases](https://github.com/mapherez/nox-auth/releases).

## 0.0.2

- Add the private `/v1/admission` endpoint for registered applications checking central admission after authenticating their own independent credentials.
- Keep independent API-key admission separate from browser-session logout, with bounded reuse and no extension of derived authority from stale admission.

## 0.0.1

- Provide headless Google-backed NoX Login with an OIDC provider and private same-host exchanges.
- Persist identity, signing/encryption keys, registered clients and renewable one-year sessions in SQLite.
- Enforce central account admission, five-minute maximum revalidation, app logout and restricted Suite logout.
- Provide reusable Go integration helpers, container/Compose configuration and a minimal environment example.
- Include security/integration tests and binary/image verification in CI and release tooling.
