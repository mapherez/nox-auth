# NoX Login integration profile

Implemented service profile, November 3, 2026. Human admission revalidation is **five minutes maximum**, approved by the owner. This document specifies Auth's API; it does not advertise OIDC certification of the complete NoX deployment or implemented product adapters.

## Protocol and transports

NoX Auth uses `github.com/zitadel/oidc/v3` `v3.51.16` as its OpenID Connect provider, `github.com/coreos/go-oidc/v3` for Google/client ID-token verification, and `golang.org/x/oauth2` for Google code exchange. Exact versions are locked in `go.mod`/`go.sum`.

Clients are **confidential web applications**, using Authorization Code, `client_secret_basic`, PKCE **S256** and query-mode callbacks. No public/native/implicit/password/client-credentials grants, wildcard callbacks, refresh-token grants or arbitrary dynamic registration are enabled. Requested scopes are limited to `openid email profile`, with `openid` mandatory. State and nonce must each contain at least 22 characters of unpredictable data; the provided client generates 32 random bytes.

The provider's ordinary confidential web-client validation accepts exactly registered HTTP callbacks for code flow, with `DevMode=false`. HTTPS callbacks use the same exact matching. Private HTTP/IP/home.arpa callbacks therefore do not need a Google registration or per-app certificate. An HTTP app connection remains HTTP; HTTPS on Auth does not encrypt it. This is a deliberately specified private-origin deployment profile, not a claim of meeting every stricter OAuth deployment profile.

The issuer is the configured public HTTPS origin. It is fixed in persistent storage and does not follow untrusted Host/Forwarded headers. Changing the URL of an existing installation requires an explicit issuer transition; startup refuses to silently change the persisted identity.

| Interface | Reachability | Routes |
| --- | --- | --- |
| Browser/metadata | TCP behind the configured HTTPS proxy/tunnel | GET `/authorize`, `/login`, `/auth/google/callback`, `/authorize/callback`, `/.well-known/openid-configuration`, `/keys`, `/healthz`, `/readyz`, `/` |
| Runtime application | `/run/nox-suite/nox-auth.sock` only | POST `/oauth/token`, `/oauth/introspect`, `/revoke`, `/v1/logout`; GET/POST `/userinfo`; GET metadata/keys/health |
| Setup administration | `/run/nox-auth-admin/control.sock` only | PUT/DELETE `/v1/clients/{client_id}` |

The two local directories are configurable; use their documented container mounts by default. Filesystem socket permissions are `0660`; the shared group is GID `10001` in the container. The Auth user is UID `10004`. A lock prevents another process from replacing an active listener; startup refuses to replace a regular file at a socket path. Supported service platforms are Linux and macOS. Runtime applications must never receive the separate administrator mount.

Public metadata retains HTTPS endpoint URLs even though confidential exchanges are only accepted over Unix transport. The Go client connects those exact issuer URLs through the local socket without changing the verified issuer, disabling TLS verification for unrelated hosts, or sending client secrets through the public proxy. Other languages can implement the same HTTP-over-Unix transport. Standard clients must configure that transport; a remote TCP token request cannot work in this same-host profile.

## Authorized registration

Registration is authorized by possession of the separately restricted administration socket. Do not proxy that socket, put it in the ordinary shared transport volume, or give it to an untrusted/runtime product. Only explicitly designated setup controllers may mount it. This is not an endpoint for any product to self-authorize using its runtime service credential.

PUT `/v1/clients/{client_id}` with JSON:

```json
{
  "client_secret": "a-cryptographically-random-value-of-at-least-32-bytes-base64url",
  "redirect_uris": ["http://product.home.arpa/auth/nox/callback"],
  "suite_logout": false
}
```

The secret is generated/persisted once by the authorized controller, not supplied by a human for each product and not regenerated on every restart. The service stores its SHA-256 hash and compares it in constant time. Client IDs match `[a-z][a-z0-9-]{1,62}`. Register 1–8 exact HTTP(S) callback URLs with a path, without credentials, wildcard, query or fragment. Register separate IP and hostname callbacks explicitly if both are supported by that app; do not derive callbacks from untrusted incoming headers.

Success is HTTP 200 with `client_id`, `redirect_uris`, `suite_logout`; it does not echo the secret. Repeating an unchanged registration is safe. Changed registration invalidates existing app credentials and pending login requests. DELETE removes admission for that client and revokes its tokens. `suite_logout: true` is an additional administrative client capability reserved for the designated dashboard/Portal controls, rather than every runtime app.

The Go `client.Register` helper operates on this socket. Its caller must be the authorized setup controller. Its future integration into Yard/Backend setup remains separate work; Auth does not modify either product to mount its administrative capability automatically.

## Login and browser transaction binding

1. The app creates a random state, nonce and PKCE verifier. Persist the transaction in a short-lived, **single-use, browser-bound** server-side store, retaining the original safe local return path. The Go `Begin` helper produces these values and the authorize URL; it does not store the browser transaction for the app.
2. The browser visits `/authorize` with `response_type=code`, exact `client_id` and `redirect_uri`, `scope=openid email profile`, state, nonce, `code_challenge` and `code_challenge_method=S256`.
3. The provider validates the registered client/callback and directs the browser through `/login`. A valid Auth cookie is reused; `prompt=login/select_account` or a required `max_age` can force Google. `prompt=none` without a valid session returns `login_required` without opening Google.
4. Google returns to `${NOX_AUTH_PUBLIC_URL}/auth/google/callback`. Auth binds its own Google transaction to an HttpOnly, Secure, SameSite=Lax browser cookie, nonce and Google PKCE verifier. It consumes that transaction once, verifies the signed Google ID token and allows only a verified email in the central list. Google tokens are discarded after identity verification.
5. Auth establishes its own persistent session and returns a single-use code and the original state to the exact app callback.
6. The app atomically consumes its own browser-bound transaction, compares state, and POSTs the code/redirect URI/verifier to `/oauth/token` with Basic client authentication through the runtime socket. The app validates the returned ID token: issuer, ES256 signature, audience, expiry, nonce and access-token hash binding. Wrong or expired state/code/verifier/client/callback is denied. A failed attempt may consume the code; restart login rather than retrying an uncertain exchange.
7. Remove the temporary callback query with a redirect to the safe original app path. Create an opaque app session cookie and keep Auth credentials **only on the server**. Do not render tokens in an HTML page, URL, browser storage or logs.

The Google callback and the app callback are separate. The app's own transaction validation is mandatory even if Auth successfully authenticated the user. App login/logout endpoints require the normal browser CSRF/origin protections; a shared Auth session does not replace them.

Public login endpoints share a process-local limit of 20 requests/second with a burst of 40. Pending request storage is bounded and expired transaction records are cleaned up. This does not make metadata health a Google reachability check.

## Identity and session credentials

ID tokens use a persisted ES256 key and a five-minute lifetime. The stable identity is `(iss, sub)`. Verified email/profile claims accompany `nox_admin: true` for centrally admitted accounts, and `google_sub`/`google_iss` support linking an existing trusted Google identity during product adaptation. Do not use email alone to attach an unrelated existing user's data.

The opaque access token is an **app-bound server-side session credential**, with a renewable one-year lifetime. It is not a Backend API key or an MCP delegation. No Google refresh token is required. The encrypted token contains an opaque token identifier/subject, and its record is bound to the originating Auth browser session and application. Deleting/revoking the root session invalidates all derived app credentials. Client removal, local token revocation, expiry and current account admission are checked server-side.

After code exchange, instantiate `client.NewSession(credentials)` in the app's server-side session handling. Its `Authenticate` method checks `/oauth/introspect`, with Basic client authentication and form field `token`. The app must bind that stored credential to its own browser cookie; never accept a credential chosen by the browser as the authenticated server record.

A successful introspection includes `active`, `client_id`, stable identity/admin claims and the rolling `exp`. A positive result may be reused for **at most five minutes from the start of the check**, never beyond its validity. The supplied Session helper enforces this bound and prevents a denied session from being resurrected. On expiry it requires fresh validation. Errors do not extend the previous result. Idle sessions require no polling. Persist renewed credentials/session expiry in the app's own store where applicable; recreating the in-memory helper simply requires a fresh admission check.

Auth renews session records with use. The browser's Auth cookie must also be renewed through a top-level Auth redirect before its expiry: the helper's `BrowserRenewAt`/`NeedsBrowserRenewal` schedules this at 30 days. The normal login round trip reuses Auth and returns to the same app page without another Google selection. Reset this date from the fresh credentials. This is separate from five-minute server-side revalidation.

## Logout and account removal

POST `/v1/logout` over the runtime socket, with Basic client authentication and JSON:

```json
{"token":"the-app-bound-server-side-access-token","scope":"app"}
```

`app` revokes that app's session credential. The application also invalidates its own session/cookie and displays its signed-out page, without immediately triggering another login. Other app sessions and Auth SSO remain valid.

`suite` additionally requires the caller client's `suite_logout` capability. It revokes the originating Auth browser session and all derived app credentials, including the invoking app. HTTP 204 means revocation was committed; an error must not be presented as successful Suite logout. Other apps stop accepting their cached confirmations within five minutes. Independent sessions on other devices remain separate. Google and persistent Discord linkage are not revoked. Backend's dashboard, then Portal, will own that UI in their adaptation work; Auth supplies no logout dashboard.

After central allowed-email configuration is applied, Auth immediately refuses a removed account and marks its existing root sessions revoked in persistent storage. Subsequent app checks return inactive; positive checks made before removal remain bounded by the same five-minute limit. Reinstating the email does not un-revoke old sessions. Applying environment changes means recreating with the same data volume and updated environment, rather than just editing a file.

All allowed accounts currently receive the common administrative admission signal; no local per-app admission list or extra role editor is introduced. Products retain domain/data/platform restrictions. A login token is not permission for Yard's service credential to approve its own Backend deployment association. The human-action-to-Backend authorization adapter must still be specified in that product work.

## Operational boundaries and acceptance

Keep Auth data and administrator mounts private, use the normal platform volume permissions, and route only browser/metadata TCP traffic through the Auth public proxy. Do not publish Unix sockets over TCP. Never put generated credentials into source control. Back up the Auth data volume; ordinary update/recreate must retain it. Startup uses static Google metadata and does not depend on Google's discovery endpoint being available. A new Google exchange/JWKS refresh requires Google connectivity; ordinary session checks use local state.

CI and local tests exercise real HTTP OIDC code exchange, private hostname/IP callbacks, SSO between independent clients, forgery/binding/replay/expiry/concurrent redemption rejection, local/global logout, account removal/re-add, persistent signing/encryption state and bounded cache/outage behavior. Google validation uses signed tokens and a controlled JWKS/token server. A successful real Google login and the first installed Yard adapter remain acceptance work with the operator's actual configuration; they are not inferred from fixture tests.
