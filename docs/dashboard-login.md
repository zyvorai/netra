# Signing in to the dashboard

The web dashboard is now gated behind a login screen instead of the old inline
"API token" field that used to appear on every page.

![Sign in](ux/07-login.png)

## Default credentials

| Field    | Value       |
|----------|-------------|
| Username | `admin`     |
| Password | `Admin@321` |

Open `https://<controller-host>:30870/` (the port and TLS default come from
[HTTPS default](../README.md#https-default)) and sign in with the credentials
above. The login screen shows the host you're connecting to ("Connecting to
`<host>`") so you can confirm you're pointed at the right cluster before
entering credentials — useful when you manage more than one Netra
deployment.

If the controller was installed with a **custom** `NETRA_API_KEY` /
`auth.apiKey` (for example `openssl rand -hex 32`), sign in as `admin` and
paste that API key as the password. The UI probes `/api/v1/fleet` with the
bearer before opening the dashboard, so a wrong key fails on the login
screen instead of bouncing you after a brief flash of the console.

`scripts/deploy-remote.sh` defaults `NETRA_API_KEY` to `Admin@321` so the
demo pair works after a remote deploy unless you override it. The same
script writes `~/.netra/api-key` and `~/.netra/env` so `netractl status`
works without hand-exporting TLS or URL settings — see
[`netractl.md`](netractl.md).

## What the login actually does

Netra's controller has one shared bearer secret (`NETRA_API_KEY`, see
[Safety and persistence](../README.md#safety-and-persistence)) — there is no
per-user account system in `netrad` today. The login screen is a **frontend
convenience gate**: entering `admin` / `Admin@321` maps to that one bearer
token client-side and stores it the same way the old token field did
(`localStorage`), then every dashboard API call authenticates with it as
before. It does not add a new server-side access-control layer — anyone who
can reach the controller's port can already load the unauthenticated static
UI shell (only the `/api/v1/*` calls require the bearer token) — it only
removes the friction of copy-pasting the token into the UI by hand.

Logging out (the exit-arrow icon button next to the theme toggle in the top nav) clears the stored token
and returns you to the login screen. If the controller ever rejects a request
with `401` (e.g. the API key was rotated on the controller since you signed
in), the dashboard automatically clears its stale token and returns you to
the login screen instead of showing a dead page.

## Changing the password

Because the login is a client-side mapping rather than a server-side account,
"changing the password" means keeping two things in sync:

1. The controller's real bearer token — set via `NETRA_API_KEY` (see
   [Standalone Helm install](../README.md#standalone-helm-install) /
   `scripts/deploy-remote.sh`) or the Helm chart's `auth.apiKey` value.
2. The login form's expected username/password and the token it maps to —
   `USERNAME`, `PASSWORD`, and `API_TOKEN` in `web/src/auth.ts`.

If you rotate `NETRA_API_KEY` on the controller, update `API_TOKEN` in
`web/src/auth.ts` to match (and change `PASSWORD` too if you want a new
login password) before rebuilding and redeploying the web bundle. Because the
login page's password field never leaves the browser, this is not a stronger
credential than the bearer token itself — anyone who has the token
effectively has the password already. Treat it with the same care as the
`NETRA_API_KEY` secret.

## Netra is a Zyvor project

The dashboard carries [Zyvor](https://zyvor.dev)'s branding in two places: the
top nav uses Zyvor's bare orange "Z" logomark (matching the mark in Zyvor's
own site header), while the login screen and browser favicon use Zyvor's
filled gradient tile mark. Netra is Zyvor's open-source eBPF observability
product ([Zyvor product page](https://zyvor.dev/netra)).
