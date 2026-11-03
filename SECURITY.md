# Security boundary

NoX Auth trusts Google ID tokens only after signature, issuer, audience, expiry, nonce and verified-email validation. The configured central allowlist controls admission. All currently admitted identities receive the common administrative identity signal; product rules still apply.

Public TCP serves login redirects/callbacks, public metadata/keys and health only. Token exchange, session checks and logout are private to the same-host Unix runtime socket and authenticated clients. Client enrollment is restricted to a separate administrative socket/volume: possessing that mount grants client-management authority. Do not distribute it to runtime apps. An ordinary Suite socket mount, a URL or matching IP is not client enrollment authorization.

The Google-facing origin is HTTPS. Internal application callbacks can be exactly registered HTTP URLs under the confidential-client profile; HTTP does not provide transport encryption. Authentication codes remain PKCE/client-bound, and confidential exchanges use the local socket. This profile does not add manual certificate distribution to applications or permit remote Suite services.

Preserve and protect the data volume: it contains signing/encryption keys and account/session state. Tokens remain in application server storage; app cookies carry only that app's opaque session credential. Secret values, codes, states and cookies must not be logged by adapters or reverse proxies. The service sanitizes provider state/redirect/error-parent log attributes and does not enable HTTP access logging.

Apps must enforce the five-minute maximum admission reuse, deny on expired confirmation when Auth is unavailable, protect browser login/logout transactions against CSRF and use the configured exact callback rather than trusting forwarded headers. Auth revocation is not immediate propagation to a consumer with a still-valid cached decision. Backend MCP delegations have their separate contract expiry and must not be extended using stale Auth admission.

Report a suspected vulnerability privately to the repository owner. Do not post live credentials, session tokens or database contents in issues.
