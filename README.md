# NoX Auth

One Google-backed login for your NoX apps.

NoX Auth provides the **NoX Login** button used by participating apps. Click it, choose your allowed Google account and return to the app you were opening. If you are already signed in, another participating app can reuse that sign-in.

Configure your Google credentials and allowed accounts once, in Auth, instead of repeating the setup in every app.

- Only the Google accounts you explicitly allow can sign in.
- Shared sign-in across participating NoX apps.
- Persistent sessions across normal service restarts.
- Sign out of one app, or use Backend's shared logout control.

Auth runs in the background and has no management dashboard. You manage its settings through the container's environment. Each app keeps its own interface and application data.

## What you need

- Docker with Docker Compose on the same host as your participating NoX apps.
- A Google OAuth web application with a client ID and client secret.
- An **HTTPS address for Auth**, served by your reverse proxy or tunnel.

Only Auth's Google-facing address requires HTTPS. Your apps can keep their private HTTP addresses. The Google credentials belong only in Auth; you do not need a separate Google client for each app.

## Help

[Application integration and troubleshooting](docs/integration.md) · [Login and session reference](NOX_AUTH_CONTRACT.md) · [Security reporting](SECURITY.md)

## Usage

### Install

On your Docker server, download the deployment files into a new folder:

```sh
mkdir nox-auth
cd nox-auth
curl -fsSLo docker-compose.yml https://raw.githubusercontent.com/mapherez/nox-auth/main/docker-compose.yml
curl -fsSLo .env https://raw.githubusercontent.com/mapherez/nox-auth/main/.env.example
```

Open `.env` in a text editor and set:

| Setting | What to enter |
| --- | --- |
| `NOX_AUTH_PUBLIC_URL` | Your Auth HTTPS base address. |
| `NOX_AUTH_GOOGLE_CLIENT_ID` | Your Google OAuth web application's client ID. |
| `NOX_AUTH_GOOGLE_CLIENT_SECRET` | Its client secret. |
| `NOX_AUTH_ALLOWED_EMAILS` | The Google account emails allowed to sign in, separated by commas. |

In your [Google Cloud Console](https://console.cloud.google.com/), configure the OAuth web application's authorized redirect URI as your Auth address followed by **`/auth/google/callback`**. Keep `.env` private.

The supplied Compose file publishes Auth's **HTTP** listener on host port **5712**. Point your HTTPS proxy or tunnel to that listener using **HTTP** as the upstream protocol. Do not select HTTPS for the upstream unless you separately configured it there. If you change the host port with `NOX_AUTH_PORT`, update the upstream destination to match.

Start Auth:

```sh
docker compose pull
docker compose up -d
```

Open your Auth HTTPS address followed by `/healthz`; a working service returns `{"status":"ok"}`.

### Use NoX Login in an app

Start Auth before Backend or Yard. In each app's configuration, set `NOX_AUTH_PUBLIC_URL` to the same Auth address. Their supplied Compose files register their login callbacks automatically through the shared local volumes.

Open the app and choose **NoX Login**. Use one of the accounts listed in Auth's `.env`. Other accounts are refused. There is no separate Auth dashboard to open first.

### Update or change allowed accounts

After editing `.env`, apply it from the installation folder:

```sh
docker compose up -d
```

To update the service image as well:

```sh
docker compose pull
docker compose up -d
```

Keep Auth's data volume: it holds the keys, registered apps and session state. Removing an email from the running configuration also invalidates its existing sessions within **five minutes**; it does not depend on asking Google to sign in again. See [logout and account removal](docs/integration.md#logout-and-account-removal).

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
