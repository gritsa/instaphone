# Instaphone — Browser-Based Twilio Softphone

A pure-frontend, single-page Twilio Voice softphone. No backend server required —
access tokens are minted **in your browser** using your own Twilio API credentials.

> ⚠️ **Personal use only.** Because tokens are minted client-side, your API Key
> Secret lives in the browser (localStorage + memory). This is convenient for a
> personal dialer but is **not a secure architecture for distribution**. Never
> deploy this publicly or share it with others. See [Security caveats](#security-caveats).

## Features

- **Onboarding** — enter Twilio credentials once; stored in `localStorage` only
  after you tick the confirmation checkbox and submit.
- **Client-side token minting** — HS256 JWTs signed with the Web Crypto API
  (async HMAC), following Twilio's access-token format, with a Voice grant.
- **Outgoing calls** — dial pad (0-9, `*`, `#`, backspace), click-to-dial from
  contacts and call log, in-call mute / hold (DTMF `*2`) / hang-up.
- **Incoming calls** — the device registers against Twilio's Voice infrastructure
  under your chosen client identity, so the browser rings with accept/reject UI.
- **Contact book** — localStorage-backed, add/edit/delete, click-to-dial.
- **Call log** — newest-first history with direction, number/name, timestamp,
  duration/outcome.
- **Danger zone** — one button to wipe credentials, contacts, and call log.
- **Light & dark themes** — toggle from the topbar; the choice is remembered
  (`localStorage['instaphone.theme']`), defaulting to your OS preference.

## Files

| File         | Purpose                                  |
|--------------|------------------------------------------|
| `index.html` | Markup for all screens and modals        |
| `styles.css` | Light & dark themes (CSS custom properties)   |
| `app.js`     | All logic (JWT, Voice SDK, storage, UI)  |

The Twilio Voice SDK is loaded from Twilio's CDN — no bundler or `npm install`
needed.

## Running

Any static file server works. For example:

```bash
# from this directory
python3 -m http.server 8080
# or
npx serve .
```

Then open <http://localhost:8080>.

> **Important:** serve over `http://localhost` or `https://` — Web Crypto
> (`crypto.subtle`) and microphone access require a secure context. Opening the
> file directly via `file://` will not work.

## Deployment (GitHub Pages)

The app is a fully static, client-side site — there is **no build step**. The
repo ships with a GitHub Actions workflow (`.github/workflows/deploy.yml`) that
deploys it to GitHub Pages on every push to `main`.

To enable it:

1. Push the repo to GitHub.
2. Go to **Settings → Pages** and set **Source** to **GitHub Actions**.
3. Push to `main` (or run the workflow manually via **Actions → Deploy to
   GitHub Pages → Run workflow**). The site will be live at
   `https://<user>.github.io/<repo>/`.

Notes:

- **HTTPS is required and provided.** Web Crypto (`crypto.subtle`) and
  microphone access only work in a secure context. GitHub Pages serves over
  HTTPS, so the app works there out of the box (as it does on
  `http://localhost`).
- **Subpath-safe.** All asset references are relative paths, so the site works
  under a project-page subpath like `/instaphone/` without configuration.
- **`.nojekyll`** is included so GitHub Pages serves the repo's files as-is
  (skipping Jekyll processing).
- **Still personal-use only.** Hosting the site publicly does not make the
  client-side token-minting model safe for distribution — anyone who uses it
  must enter their *own* credentials, and those credentials live in *their*
  browser only. See [Security caveats](#security-caveats).

## Theme toggle

The sun/moon button in the topbar switches between dark and light modes. The
choice persists in `localStorage['instaphone.theme']`; with no saved choice the
app follows your OS `prefers-color-scheme` (and reacts live if you change it).
The theme is applied by an inline script in `<head>` before first paint, so
there is no flash of the wrong theme on load.

## Settings tab

Once onboarded, the **Settings** tab shows your persisted credentials on every
page load (read from `localStorage['instaphone.credentials']`). The API Key
Secret is never displayed — the field shows a `••••` mask instead. Leave the
mask as-is to keep the saved secret; type a new value to replace it. Saving
validates the SID formats, writes back to localStorage, and reconnects the
device. The **Reconnect** button re-registers without changing anything, and
**Clear all data** (Settings tab) wipes credentials, contacts, and call log after
confirmation.

## Twilio setup

### 1. Create an API Key

In the [Twilio Console](https://console.twilio.com/) → **Account → API keys & tokens →
Create API key**. Choose **Standard** type. Copy the **SID** (`SK…`) and **Secret**.
You'll also need your **Account SID** (`AC…`).

> Tip: use a dedicated, restricted API key — not your main account auth token —
> so you can revoke it easily if the browser profile is ever compromised.

### 2. Create a TwiML App

**Voice → TwiML Apps → Create new TwiML App**. Copy the App SID (`AP…`).

Under **Voice Configuration**, set the **Request URL** for when a call is
received. A minimal TwiML bin that dials your browser client:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Dial>
    <Client>browser-user</Client>
  </Dial>
</Response>
```

Replace `browser-user` with whatever **client identity** you entered during
onboarding (default: `browser-user`).

### 3. Route incoming calls to the browser

For a browser to ring, the incoming call's TwiML must contain a
`<Dial><Client>your-identity</Client></Dial>` verb. Common setups:

- **PSTN calls to your Twilio number** → point the number's voice webhook at the
  TwiML App (or a Twiml Bin with the XML above).
- **Client-to-client calls** → another Voice SDK endpoint dials
  `client:browser-user`; Twilio routes it to whichever registered device holds
  that identity.

### 4. Outgoing calls

When the browser places a call, Twilio hits your TwiML App's **Voice Request
URL** with a `To` parameter (the number you dialed). A minimal TwiML App handler
that dials the requested number:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Dial callerId="+1YOUR_TWILIO_NUMBER">{{To}}</Dial>
</Response>
```

(Using Twilio Functions instead of static TwiML lets you read `To`
dynamically — see Twilio's "Voice SDK quickstart" for a ready-made Function.)

### 5. Required permissions

- The **API key** must be able to mint Voice access tokens (Standard keys can).
- Your Twilio account needs **Voice enabled** and, for outbound PSTN calls, a
  verified **caller ID** or an owned Twilio number to use as `callerId`.
- The browser will prompt for **microphone** permission on the first call —
  grant it.

## Using the app

1. Open the app → the onboarding form appears.
2. Enter Account SID, API Key SID, API Secret, TwiML App SID, and (optionally)
   change the client identity.
3. Tick the confirmation checkbox and click **Save & Connect**.
4. The status pill in the header should turn green: **Registered · your-identity**.
5. Dial a number (E.164 format like `+15551234567` works best) and hit **Call**,
   or add contacts and click-to-dial.

## Do you need a persistent server? (short answer: not for this app — yes for production)

**For this app, as built: no server is required, and that is by design.** The
Twilio Voice JS SDK does not care *where* a token was minted — its validator is
pure JWT verification: it reads the `iss` claim, looks up that API key's
secret, and checks the HMAC. A client-minted HS256 token is byte-for-byte
identical to one minted by the official server-side SDK (proven by
`npm run diff-token`). There is no technical requirement — no region/edge
config, no server-side SDK handshake — that forces a backend for registration
or calls to work.

**For anything beyond personal single-user use: yes, you need a token-serving
endpoint, and this is non-negotiable.** The reason is not validation — it's
secret exposure. Minting in the browser means your API Key Secret lives in
`localStorage` and in browser memory. Anyone with access to that browser
profile (malware, a shared machine, or an XSS bug if you ever host this
somewhere public) can exfiltrate the secret and mint unlimited tokens on your
account until you delete the API key. A production architecture is:

```
Browser ──(fetch /token?identity=me)──▶ Your backend (Twilio Functions,
                                        Express, etc. — holds the secret)
        ◀────── short-lived JWT ───────
        ──(register/dial with token)──▶ Twilio
```

The backend mints with `twilio.jwt.AccessToken` (the secret never leaves the
server), issues short-lived tokens per user, and can enforce per-user
identities and revocation. This repo deliberately does **not** do that — it is
a personal tool, and the onboarding screen warns you accordingly. If you ever
want to share or deploy it, add a token endpoint and delete the client-side
minting path.

## Security caveats

- **Client-side token minting is for personal use only.** The API Key Secret is
  stored in `localStorage` and used in-browser. Anyone with access to that
  browser profile (malware, shared machine, XSS in a hosted deployment) can
  steal it and make calls on your account.
- **Never distribute or host this publicly.** A production softphone must mint
  tokens on a backend (e.g. Twilio Functions, or your own server using the
  official `twilio` helper library) so the secret never reaches the client.
- Tokens expire after 1 hour; the app re-mints and refreshes automatically via
  the SDK's `tokenWillExpire` event.
- Use the **Clear all data** button (Settings tab) to wipe credentials,
  contacts, and the call log from the browser before walking away from a shared
  machine.

## Troubleshooting

### AccessTokenInvalid (20101): "Twilio was unable to validate your Access Token"

The app now logs the **decoded token payload** (never the secret) to the browser
console whenever device setup fails or Twilio returns 20101 — look for the
`[device-setup]` / `[twilio-20101]` entries. Verify against that output:

1. **`iss` must be your API Key SID (`SK…`)** — this is the #1 cause of 20101.
   Twilio's validator resolves *which* API key (and therefore which secret) to
   verify the signature with by looking up the `iss` claim. If `iss` is the
   Account SID, the lookup fails and the token is rejected **even though the
   signature itself is perfectly valid** (which is why `jsonwebtoken.verify`
   passes but Twilio's servers reject it). `sub` must be the Account SID (`AC…`).
2. **`grants.voice.outgoing.application_sid` must be your TwiML App SID (`AP…`)**.
3. **`grants.identity`** must match the client identity you dial
   (`<Dial><Client>…</Client></Dial>`).
4. **`exp` / `iat` / `nbf` must be numeric epoch seconds** and `exp` in the future.
5. If all of the above look right, the remaining causes are credential-side:
   - **Wrong API Key ↔ Account pairing** — the key must belong to *this* account
     (check the key's Account SID in Console → Settings → API Keys).
   - **Bad API Secret** — the secret is shown only once at key creation; if lost,
     create a new API key. A wrong secret produces exactly this 20101 error.
   - **Clock skew** — if your machine's clock is minutes off, `nbf`/`iat` can be
     "in the future" from Twilio's perspective. The app backdates `iat`/`nbf` by
     30 s to absorb minor drift, but a badly skewed clock (minutes/hours) will
     still fail. Check with `curl -sI https://twilio.com \| grep -i ^date` vs
     your local time.

You can also validate the minting logic offline (no real credentials needed):

```bash
npm install
npm run verify-token
```

This reproduces the exact token the browser mints, checks every claim against
Twilio's spec, and verifies the HMAC signature with `jsonwebtoken`.

For a definitive structural check, you can diff the browser-minted token
byte-for-byte against one minted by Twilio's **official** Node SDK:

```bash
npm run diff-token
```

This prints both tokens' headers/payloads and reports `SAME`/`DIFF` per claim.
The app's minting code was built to match the official SDK exactly — as of the
`iss` fix above, every field is `SAME`.

### Other symptoms

| Symptom | Fix |
|---|---|
| Status stays "Connecting…" | Check the browser console; usually a bad SID/secret or the TwiML App SID doesn't exist. |
| "Registration failed" / 31201 | The access token was rejected — verify API Key SID/Secret and Account SID. |
| Incoming calls don't ring | The caller's TwiML must `<Dial><Client>your-identity</Client></Dial>` and the identity must match exactly. |
| No audio | Check microphone permission and that you're on `https://` or `localhost`. |
| Outbound call fails immediately | Your TwiML App's Voice Request URL must return valid `<Dial>` TwiML with a valid `callerId`. |
