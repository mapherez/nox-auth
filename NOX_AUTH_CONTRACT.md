# NoX Auth — NoX Login contract

Decision record: **November 3, 2026**.

Status: **agreed product requirements; five-minute access revalidation confirmed by the owner on November 3, 2026**. Service implementation and the Go client are provided in this repository; [the integration profile](docs/integration.md) records the selected protocol, exact endpoints and private-origin behavior. Product adaptations and real installed Google/Yard acceptance remain separate work. This document does not change released NoX MCP wire contracts.

## 1. Purpose and scope

NoX Auth is the shared Google-backed login service for any current or future NoX application. Users sign in through a **NoX Login** button and return to the application they opened. Applications consume the same integration contract, without implementing Google login or maintaining separate account allowlists.

NoX Auth is a running service/container, not just a library installed in every application. It has **no frontend or management dashboard**. Its browser-facing functions are authentication redirects, callbacks and session endpoints. Applications display their own login controls, results and errors. Reusable integration packages may accompany the service once the protocol is specified; they do not replace it.

NoX Auth does not install containers, register product MCP servers, replace the Backend's registry or issue its personal API keys. Yard retains deployment/lifecycle responsibilities; Backend retains registration and delegated operation authorization; Gateway retains MCP routing; CLI remains a separate product.

## 2. Configuration and installation

Run one Auth service for the installation, alongside the participating products on their shared host. It must be usable in any installation, without hardcoded hostnames, addresses, network ranges or paths from the author's homelab.

Operator-supplied configuration consists of the Auth public HTTPS origin, Google client ID and secret, the allowed Google account emails, and deployment configuration. These Google credentials and the account-admission list belong **only to Auth**, not to every application. The implementation must document its exact environment-variable names and provide a minimal `.env.example` and normal container deployment instructions.

The operator registers the Auth Google callback in Google Console. An existing HTTPS reverse proxy or tunnel may expose Auth. Internal application URLs can remain private; they are not registered with Google and do not need public tunnels solely for NoX Login. Do not add manual certificate generation or distribution as a Suite prerequisite.

Auth creates and persists its own signing material, stable identity bindings and session state in its documented data volume. Restarting or recreating the container with that volume, including ordinary updates, must retain identities and valid sessions. Do not regenerate the issuer identity or signing secrets on every startup. Configuration errors must be actionable and must not expose secrets.

Applications need their own registered identity, approved callback URLs and authenticated server connection to Auth. Enrollment must follow the existing authorized same-host setup: no hand-copied Google secrets, protocol JSON or account lists for every product. Exact client provisioning is part of the protocol specification, not an excuse to introduce an unapproved deployment manager or additional setup dashboard.

## 3. Identity and authority

Auth verifies Google identity and checks the central allowlist before granting entry. Another Google account is refused even if Google successfully authenticates it. Validate Google's issuer, audience, expiry, transaction binding and verified email; bind the account to Google's stable provider subject rather than using a mutable display name as identity.

Applications trust the configured Auth issuer and a stable subject belonging to that issuer. They validate the identity response and current admission state. They must not accept arbitrary JWTs, email strings, or browser claims as authenticated identity. Only Auth holds Google credentials; applications do not receive Google access or refresh tokens as their dashboard credentials.

The intended access policy is the same authorized Google identity across NoX applications, including Suite administrative access. Products must consume central admission/administrative authority instead of requiring a second local administrator approval or separate allowlist. This does not introduce a new per-user/per-tool permission editor. Existing data ownership, domain validity, confirmation and external-platform permissions remain enforced.

A human administrator and a service are different actors. Logging into Yard through Auth does **not** turn Yard's service credential into an administrator credential. Backend continues to require authorized administration for deployment associations. The rejected installer self-authorization must remain absent. The future adapter must bind an authorized user's deployment action to the intended registration operation without forwarding browser cookies or a personal API key as the Yard service identity. Its concrete authorization flow must be specified before changing those checks; shared login alone does not implement that flow.

## 4. Browser login journey

1. The user opens an application's ordinary address and selects **NoX Login**.
2. The application starts a login transaction bound to that browser, its registered client identity and exact approved callback. It keeps a safe local return path for the original page.
3. The browser visits Auth over its configured HTTPS origin. If an Auth session is already valid and allowed, Auth reuses it. Otherwise Google handles account selection and authentication.
4. Google returns to the **Auth Google callback**. Auth validates the Google response and the central account-admission policy.
5. Auth returns the browser to the **application's registered callback** with a short-lived, single-use authorization result bound to the original transaction and client. Long-lived credentials must not travel in browser URLs.
6. The application's server validates/redeems the result with Auth, creates its own session and returns the browser to the original safe application page.

For example, `http://yard.home.arpa/` can be the starting and return origin while the Google callback belongs to the configured Auth HTTPS domain. These are two different callbacks. Opening another app with the same browser/profile reuses the Auth session; it must not require another Google account selection merely because the application differs.

Callback addresses are registered exactly, not arbitrary `return_to` destinations supplied by a browser. Reject mismatches, open redirects, replay, cross-client substitution and cross-browser/login CSRF. Validate state and nonce and use code binding such as PKCE S256 in the specified protocol. Keep application return paths local and remove the temporary authorization result from the visible URL after processing. Never log codes, cookies, secrets or session credentials.

## 5. Protocol and transport boundary

The selected protocol is **OpenID Connect Authorization Code flow** using confidential web clients, Basic client authentication and mandatory PKCE S256. The ZITADEL OIDC library accepts exact registered HTTP code-flow callbacks with `DevMode=false`; Google/client ID tokens are validated with the CoreOS OIDC library. Exact locked versions and the Unix-transport profile are documented in [the integration profile](docs/integration.md). This is not a claim that arbitrary OIDC clients/providers support every private-origin deployment, or certification of the full application.

The required product behavior includes configured internal HTTP and HTTPS application origins, including hostnames and private IP addresses. The implementation must resolve that requirement explicitly against the selected protocol's redirect, cookie and token-exchange rules. If a candidate cannot support the agreed deployment, report the concrete incompatibility before changing the requirement. Do not silently require certificates on every app or disable a provider's validation to make it work.

Auth's Google-facing origin/callback uses HTTPS. This protects that connection and satisfies Google's web callback requirements; it does not encrypt a separate HTTP application connection. A browser callback to a private app is a browser journey, not permission for remote products to join the Suite. Authenticated server-to-server communication between Suite products retains the approved same-host boundary; a URL or matching IP address is not proof of membership.

The existing shared local channel and authorized enrollment must be reused for private exchanges where applicable. This contract does not expose service credentials, token redemption or administrative operations anonymously through the public Auth ingress. Public login entry points must validate registered clients and browser transactions; they must not accept arbitrary product registration.

## 6. Sessions and logout

### Session duration

Human login sessions last **one year, renewable with use**. Renewal requires the account and session still to be allowed. A valid Auth session permits another NoX application to establish its own session without repeating Google account selection. Each application has its own session cookie; unrelated domains do not share a cookie.

Cookies and server records must have consistent renewable lifetimes. Persist session state across service updates. Use unpredictable credentials, protected server-side storage, HttpOnly cookies, appropriate SameSite/CSRF handling and Secure cookies on HTTPS origins. An internal HTTP origin must not be accidentally made unusable by setting an HTTPS-only cookie there. Sessions belong to a browser/profile/device; another computer may require its own login.

A year-long session is not an unconditional year-long access grant. Applications also enforce the current account/session admission described in section 7. Neither routine renewal nor revalidation requires contacting Google for every operation.

### Local logout

**Sair** invalidates the current application's session and clears its cookie. It leaves the Auth session and other applications' sessions intact. A later deliberate NoX Login may therefore sign back in without Google account selection. Logout must not immediately run an automatic login loop that defeats the user's action.

### Suite logout

**Sair de todas** is presented in the **Backend's native dashboard**, and later in the NoX Portal. It invokes Auth's authenticated session-revocation operation; it does not require an Auth frontend. It terminates the current Auth login session and the application sessions derived from it across the Suite. It does not sign out the user's Google account or disconnect Discord integrations. A separate cross-device session-management screen has not been requested.

Other applications must reject those derived sessions when notified or when they next validate them, within the agreed revocation bound. The UI must distinguish accepted revocation from a failed request; clearing only the Backend cookie is not a successful global logout. Use CSRF protection and invalidate the invoking application's session as well.

## 7. Removing an allowed account and bounded access revalidation

**Decided:** removing an allowed email must prevent both new login and continued use of existing sessions once the updated Auth configuration is applied. Changing a file alone does not change a running process's environment: document the normal restart/recreate step for applying `.env` changes. Reinstating an account must not resurrect a previously revoked session.

**Confirmed, November 3, 2026:** an application may reuse a positive admission/session check for at most **five minutes**, always bounded by the session's own validity. At the next required check it asks local Auth, not Google. Successful Auth-side revocation or account removal is denied immediately there; previously cached positive results in consumers expire within that maximum. An app performs no extra check if it has no activity. A returned denial invalidates its local session; it must not keep the user authenticated indefinitely or renew on an error.

For example, if configuration is applied at 11:00, a result obtained just before 11:00 could allow an already open app to operate until just before 11:05. Its next protected request after the cache expires must be refused. A new login after 11:00 is refused immediately. A 1–3 hour working session otherwise continues without user interaction. This is access revalidation in the background, not a Google login every five minutes.

Revocation notifications can shorten propagation; they must not extend the bound or replace expiry enforcement. If Auth cannot be reached after a cached check expires, protected access cannot be extended. No redundant Auth deployment or alternative password login is added by this decision.

The same bounded validation must cover derived app sessions after Suite logout. The confirmed maximum interval is five minutes. It is distinct from the already approved five-minute limit on Backend-signed MCP operation delegations. Backend's Auth adapter must enforce account removal for subsequent personal-key authorization and invalidate affected cached authorizations; it must not restart a fresh full cache interval from an already stale admission result. Existing, independently valid MCP delegations remain bounded by their contract expiry.

## 8. Product adaptation and data preservation

Build and validate Auth first, then integrate **Yard first** and test its actual login/logout/restart behavior before adapting Backend and the other products. This is the owner's chosen integration order, not a replacement of the complete Suite design with a temporary contract.

| Application | Agreed adaptation |
| --- | --- |
| Yard | NoX Login replaces dashboard username/password login. Preserve installation-level projects, configuration, jobs and Docker management. No extra fallback-login feature is requested. |
| Backend | Replace its own Google dashboard login with NoX Login; move Google credentials/account admission to Auth. Preserve its native frontend, existing users/data relationships, API-key services and existing client APIs. Add Suite logout control here. |
| Voice MLX | Consume NoX Login instead of its separate Google login/allowlist; preserve product functionality and state. |
| Bot | Dashboard entry uses NoX Login. Move Discord connection to a settings/integration action. Persist the Discord identity/linkage independently of dashboard session lifetime; retain the bot's own Discord token and domain permissions. Do not invent a token-refresh requirement where the existing integration only needs identity. |
| Future applications | Implement this same client integration; do not add product-specific branches in Auth. |

No standalone data-import/migration project is requested. This is not permission to delete databases, user ownership or existing configuration. Required technical identity/session adaptations must be small, explicit and preserve data. Backend must map the trusted Google identity to existing account ownership without relying solely on an unverified email or creating a duplicate user on every login.

For Yard acceptance, keep the existing administrator record/password hash and data compatible with the previous image so reverting the image restores the earlier login behavior. The new Auth-only UI does not expose a password fallback. Validate rollback with the actual database before claiming it works; require a backup if a later change cannot preserve that compatibility. Do not run destructive resets to simplify the test.

## 9. Required implementation verification

Implementation is complete only after demonstrating:

- Allowed and disallowed Google accounts, verified identity, valid callback and correct return to the original app page.
- A second app using the same browser without another Google account selection; separate devices behaving independently.
- Private hostname/IP application addresses under the specified protocol, without a per-app public tunnel or hand-created certificates.
- Rejection of altered callbacks, open redirects, invalid transaction binding, replay, cross-client substitution and forged identities.
- Renewable year-long sessions and persisted identity/session state across restart, recreate and update.
- Local logout affecting only the current app; Suite logout requested through Backend and enforced by Auth and participating apps.
- Allowlist removal applied during a valid session, bounded consumer revalidation, non-resurrection after re-adding the email, and no lifetime extension after validation failure.
- Yard data preservation and tested rollback, followed by separate acceptance of each subsequent application.
- No service self-grant, no browser-cookie forwarding as a service credential and no weakening of Backend deployment authorization.
- Portable sample configuration, container packaging and operational instructions for a different installation.

Auth tests do not certify unfinished Yard lifecycle integration, MCP descriptors, Gateway routing or the CLI. Those retain their existing scoped work and acceptance criteria.

## 10. References and implementation status

The Suite-wide plan is `Documents/NOX_SUITE_IMPLEMENTATION_PLAN.md` in `nox-mcp`; its November 3 Auth update records this new responsibility and integration order. This contract is maintained in `nox-auth/NOX_AUTH_CONTRACT.md`, not duplicated as a new provider implementation inside `nox-mcp`.

Protocol references for the implemented integration profile:

- [Google web-server OAuth and redirect validation](https://developers.google.com/identity/protocols/oauth2/web-server#redirect-uri-validation-rules): Google's registered callback belongs to Auth.
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html): standard identity/code-flow baseline, with the private-origin profile specified above.
- [OAuth security best current practice, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html): transaction/code binding and callback validation considerations.

This document does not deploy a service, publish a release, register an installed client or change an existing application. The implementation uses Go, SQLite and the maintained OIDC libraries recorded in the integration profile. Existing Yard/Backend login and Suite authorization remain unchanged until their explicitly scoped adaptations.
