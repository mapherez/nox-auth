# Changelog

## Unreleased

- Implement headless Google-backed NoX Login with a maintained OIDC provider and private same-host exchanges.
- Persist identity, signing/encryption keys, registered clients and renewable one-year sessions in SQLite.
- Enforce central account admission, five-minute maximum revalidation, app logout and restricted Suite logout.
- Provide reusable Go integration helpers, container/Compose configuration and a minimal environment example.
- Add security/integration tests, binary/image checks and gated CI/release tooling.

Existing product adapters and real installed Google/Yard acceptance remain separate work. No image or module release has been published by these changes.
