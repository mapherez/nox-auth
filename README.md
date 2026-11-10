# NoX Auth

One Google-backed login for your NoX applications.

NoX Auth provides **NoX Login**: an application sends you to the shared authentication service, you sign in with an allowed Google account, and you return to the application you opened.

Google credentials and the allowed-account list are configured in one place. Participating applications use the same identity service instead of each maintaining a separate Google login setup or account-admission list.

## What it provides

| Capability | What it does |
| --- | --- |
| Central account admission | Allows only the Google accounts configured for the installation. |
| Shared sign-in | Reuses an existing Auth session when you enter another participating app in the same browser. |
| Persistent sessions | Retains identity and session state across normal service restarts and updates. |
| Local logout | Lets an application end its own session without signing out every other app. |
| Suite logout | Supports Backend's shared-session logout control across participating applications. |
| Independent credential checks | Lets a registered application check central admission after validating its own API key. |
| Reusable client helpers | Provides a Go client for the private login and session exchanges. |

Auth is a headless service with no dashboard. Applications keep their own frontends, data and domain permissions. A login session is distinct from a Backend personal API key, a service credential or an external integration such as Discord.

## How it fits into NoX Suite

Auth runs alongside the participating applications on the same host. Its browser-facing Google callback uses HTTPS; an application's own private HTTP address does not need a separate Google client, public tunnel or manually generated certificate.

Confidential token/session exchanges use the private local channel. Login-client registration uses a separate restricted setup channel. Backend and Yard already include one-shot setup services that register their configured callbacks automatically and reuse the persisted client identity.

Auth owns admission and session revocation. Backend owns Suite registration and delegated operation authority; Yard and Gateway keep their deployment and routing responsibilities.

## Documentation

- [NoX Login contract](NOX_AUTH_CONTRACT.md)
- [Application integration and API reference](docs/integration.md)
- [Security boundary and reporting](SECURITY.md)
- [Changelog](CHANGELOG.md)

## Usage

Save [docker-compose.yml](docker-compose.yml) and [.env.example](.env.example) in a deployment directory, naming the environment file `.env`.

Configure:

- `NOX_AUTH_PUBLIC_URL`: the Auth HTTPS origin used by your browser.
- `NOX_AUTH_GOOGLE_CLIENT_ID` and `NOX_AUTH_GOOGLE_CLIENT_SECRET`: the credentials for your Google web application.
- `NOX_AUTH_ALLOWED_EMAILS`: the Google accounts allowed to sign in.

Register your configured Auth origin followed by `/auth/google/callback` as the Google application's redirect URI. Your proxy or tunnel forwards browser requests to Auth's published HTTP listener. Product callbacks are registered with Auth rather than separately with Google.

Start Auth before its consumers:

```sh
docker compose pull
docker compose up -d
```

Configure each participating application's Auth origin using that application's deployment guide. Its setup component registers the exact callback automatically; do not copy Google secrets into every product.

Keep Auth's data volume when updating. It holds signing/encryption material, clients and session state. Apply account-list changes by recreating the service with the updated environment. Revocation is enforced within the documented [session-validation bound](docs/integration.md#logout-and-account-removal); editing an environment file alone does not change a running container.

## License & Attribution

This project is licensed under the **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)** license.

### How to Credit This Project

If you use, fork, or modify this code, you **must** provide attribution by linking back to my GitHub profile. Please include the following credit notice prominently in your repository or project documentation:

> **Based on [nox-auth](https://github.com/mapherez/nox-auth) by [mapherez](https://github.com/mapherez)**
> This project includes code from [nox-auth](https://github.com/mapherez/nox-auth), used under the CC BY-NC-SA 4.0 license.

---

*For more details on what you can and cannot do, please refer to the [LICENSE](LICENSE) file in this repository.*

## Disclaimer of Warranty

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
