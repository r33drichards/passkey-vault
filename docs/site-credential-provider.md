# Experimental site credential provider

This branch adds a **software ES256 authenticator** to the existing vault plus an
unpacked Chromium MV3 extension. It is opt-in and is not deployed by building it.
The existing `/api/passkeys` remain public keys used to log in to the vault;
third-party signing credentials are separate encrypted `site-key:` records.

## Security model and limitations

- Chrome's `webAuthenticationProxy` supplies the requesting origin through its
  `remoteDesktopClientOverride` extension. The extension accepts only top-level,
  same-origin-frame requests and passes them to a pinned vault approval page.
- The vault requires its existing HttpOnly, SameSite session and same-origin POST
  checks. There is no CORS exception, public signing endpoint, or exported private
  key API. The extension receives only requests and public credential responses.
- Every operation requires a new signature by a registered SSH recovery key. The
  human-readable challenge binds the vault, site origin, RP ID, account, credential,
  full request digest, session, nonce and two-minute expiry. It is single-use even
  after failed verification. Only one approval may be outstanding per session.
- SSH authorization **is not WebAuthn user verification**. The authenticator sets
  UP, never UV. Sites requiring UV fail closed. Native platform authenticators,
  attestation, PRF, largeBlob and other unsupported extensions are not emulated.
  This means npm compatibility is **not yet proven**; do not weaken a site's policy.
- The server can decrypt keys using `VAULT_KEY`, like the existing password store.
  This is not E2EE and not equivalent to a hardware security key. Protect Worker
  access and the encryption key accordingly. Existing JSON export does NOT include
  site keys. There is not yet a credential export/import/deletion UI.
- One request at a time. Closing the approval tab, canceling the RP request or
  disabling the extension ends the request. Browser cancellation may leave an
  unconsumed server challenge until its short expiry, but never signs it.
- Completing registration is not proof the RP accepted it; a failed registration
  may leave an unused vault credential. A signature counter is committed before
  returning an assertion, so a lost response can skip a counter safely.
- Enable the proxy only while using it. It intercepts browser WebAuthn globally;
  disable it before using your normal authenticator (including vault login
  passkeys). SSH vault login remains available while it is enabled.

## Configuration (not enabled by default)

Set the Worker variable `PROVIDER_ORIGINS` to a comma-separated exact-origin
allowlist. For example, **after reviewing the deployment**, npm may need both
`https://www.npmjs.com,https://npmjs.com`: a parent RP ID must have its own explicitly
listed origin, and must be a suffix of the requesting hostname. No wildcard sites.
An empty/missing value disables all provider API routes.

The extension pins the vault origin in `extension/background.js` and
`extension/manifest.json`; change both together for another deployment. Build the
Worker with `npm run build`. Load `extension/` unpacked in Chromium developer mode,
then use the extension popup to enable it. No npm token or site password belongs
in this extension. Distribution/store packaging is a separate task.

The approval page is `/provider` (the canonical assets route for `provider.html`).
Sign into the vault first, select the registered SSH key, review the site/account,
prepare the challenge, and sign the downloaded file:

```sh
ssh-keygen -Y sign -f ~/.ssh/YOUR_REGISTERED_KEY -n passkey-vault provider-challenge.txt
```

Paste the resulting `.sig` into the approval page and explicitly approve. The
extension returns focus to the requesting tab before completing WebAuthn.

## Tests

```sh
npm ci --include=dev --legacy-peer-deps --ignore-scripts
npm run check
npm run build
npm test
```

Unit/API tests independently verify registration and assertion with SimpleWebAuthn;
cover invalid origins/RP IDs, unsupported UV/extensions, exclusion/allow lists,
encrypted storage, changed/expired/canceled/replayed approvals, session binding,
and wrong SSH signatures.

`scripts/test-desktop.mjs` is an integration harness for a **disposable localhost
vault and isolated desktop browser**, never a real account or normal profile.
Prerequisites:

1. Run the local Worker at `http://localhost:8787`, with a new disposable state
   directory. Use test-only `VAULT_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`,
   `SETUP_KEY=desktop-test-setup-key-000000000000000000000` and
   `PROVIDER_ORIGINS=http://localhost:9322` in its local `.dev.vars` (never production).
2. In a disposable copy of `extension/`, replace the production vault origin with
   `http://localhost:8787` in background.js and manifest.json.
3. Create `test-ssh-key` with `ssh-keygen -t ed25519 -N '' -f test-ssh-key` in that
   disposable project directory. It is test data; never reuse a real recovery key.
4. Start a separate Chromium profile with loopback CDP port 9333 and
   `--enable-unsafe-extension-debugging`. Do not expose CDP on a network interface.
5. Run `node scripts/test-desktop.mjs` from that disposable project directory.

The harness uses a virtual authenticator only to initialize the **test vault**,
removes it, then exercises actual browser registration and assertion via the real
extension, vault UI, SSH approval, encrypted Worker store, and independent RP
verification. It tests cancellation, browser AbortController cleanup, required-UV rejection and an unallowlisted origin. Its `approval-test.png`
is test-only UI evidence. It detaches the proxy and closes its own tabs on exit.
Stop the test Worker/browser and discard the disposable test keys afterward.

On Nix, the downloaded workerd ELF may require a local wrapper invoking the Nix
GLIBC loader. Point `MINIFLARE_WORKERD_PATH` at that wrapper; do not patch global
libraries or system configuration.

Reference: [Chrome webAuthenticationProxy API](https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy).

## Validation record (2026-10-26)

- TypeScript checks and production asset build passed.
- 49 unit/API tests passed.
- Full integration harness passed on desktop Chromium 154.0.8037.57 with a local
  Wrangler Worker: registration, assertion, independent RP verification, cancel,
  browser abort, UV-required rejection and an unallowlisted origin.
- No production vault deployment, npm enrollment, or npm publication was performed.
