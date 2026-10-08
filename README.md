# Passkey Vault

A single-owner, serverless TOTP authenticator for Cloudflare Workers. Sign in with a passkey; recover access by signing a one-time challenge with a registered SSH private key. Private SSH keys are never sent to the app.

## Features

- Passkey setup and sign-in with required user verification and discoverable credentials.
- Add TOTP accounts by scanning a QR code with your camera, uploading, dragging and dropping, or pasting a QR image with Cmd+V/Ctrl+V in Add account, pasting an `otpauth://totp` link, or entering a Base32 setup key. Camera frames and images are decoded on your device; review the detected account before saving. Search, copy codes, and remove accounts.
- SHA-1, SHA-256, and SHA-512; 6 or 8 digits; 15–120 second periods.
- Multiple registered SSH recovery public keys: Ed25519, RSA (2048–8192 bits), and ECDSA P-256/P-384/P-521. SSH certificates, DSA, and FIDO `sk-` SSH keys are not supported.
- Optional additional passkeys and an offline export of authenticator setup links.
- SQLite-backed Durable Object storage; AES-256-GCM encryption of account secrets and metadata.
- HttpOnly, SameSite=Strict sessions, same-origin mutation checks, CSP, no caching, authentication rate limits, one-use challenges, and session revocation on recovery or key removal.

## Local run

Requires Node.js 22 and npm. From this directory:

```sh
npm ci --legacy-peer-deps
node setup-local.mjs
npm run dev
```

Open `http://localhost:8787`. Read the `SETUP_KEY` value in the generated `.dev.vars` file and use it to register your first passkey. This file contains secrets; do not share it. The setup helper refuses to overwrite existing secrets.

Local and hosted passkeys are separate because their relying-party hostnames differ. Local data does not get uploaded during deployment.

## Deploy to your Cloudflare account

1. Pick the permanent hostname before creating any production passkeys. Set `vars.APP_ORIGIN` in `wrangler.jsonc` to the exact HTTPS origin, with no trailing slash. For example, `https://passkey-vault.YOUR-SUBDOMAIN.workers.dev`. You can use `--var APP_ORIGIN:http://localhost:8787` for local development after configuring production.
2. Sign in:

   ```sh
   npx wrangler login
   ```

3. Generate **independent production secrets** and save them in your password manager:

   ```sh
   openssl rand -base64 32
   openssl rand -hex 32
   ```

   The first is `VAULT_KEY`, the second is `SETUP_KEY`. The encryption key must remain stable. Replacing it will make existing encrypted accounts unreadable; key rotation is not implemented.

4. Create the Worker and its Durable Object:

   ```sh
   npm run deploy
   ```

   Until secrets are configured, API requests return 503. If the returned hostname differs from the one you configured, correct `APP_ORIGIN` and redeploy before registering a passkey.

5. Add secrets at Wrangler's interactive prompts:

   ```sh
   npx wrangler secret put VAULT_KEY
   npx wrangler secret put SETUP_KEY
   ```

6. Open the permanent HTTPS origin and register your first passkey using the production setup key. Subsequent setup attempts are disabled once a passkey is registered. Register an SSH public key in **Passkeys & SSH keys**, then test recovery before importing real accounts.

For a custom domain, configure that domain on the Worker and use it as `APP_ORIGIN`. Keep the same hostname: moving it invalidates existing passkeys. SSH recovery can register replacement passkeys after a deliberate hostname migration.

Workers and SQLite Durable Objects have free-plan allowances; this app uses no paid-only storage features. Actual usage still counts against your account limits. Cloudflare's documented free CPU allowance is small, so verify real passkey/RSA performance on your deployed Worker; local tests do not establish production CPU usage.

## SSH recovery

While signed in, paste the **public key** from your `.pub` file into **Passkeys & SSH keys → SSH recovery keys**. Key comments are ignored; the app identifies keys by their OpenSSH SHA-256 fingerprint. Key registration/removal requires authentication within the past two minutes.

If you lose your passkey:

1. Choose **Use an SSH recovery key** on the sign-in screen.
2. Paste a previously registered public key and request a challenge.
3. Download `challenge.txt`. The JSON includes the vault origin, key fingerprint, a random nonce, and expiry. Confirm that the origin is your vault's origin.
4. In the directory containing that file, sign it locally:

   ```sh
   ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n passkey-vault challenge.txt
   ```

   Use your private key's actual path. OpenSSH prompts locally if your key is encrypted. Recent OpenSSH versions with `-Y sign` support are required. An RSA or ECDSA key uses the same command with its corresponding path.

5. Paste the contents of `challenge.txt.sig` into the recovery form in the **same browser session**. The challenge expires after five minutes and is consumed by the first verification attempt. If verification fails, request and sign a new challenge.
6. Successful recovery revokes previous sessions and opens a 15-minute owner session. Immediately register a replacement passkey; then remove any lost passkey.

The SSH key is an authentication recovery key. It does not decrypt a backup independently or restore a deleted vault. Keep your production `VAULT_KEY` and an offline backup of TOTP setup links separately.

## Session and backup behavior

Server sessions last 15 minutes without sliding renewal. The UI also locks after 10 minutes without interaction. Deleting a passkey or SSH key revokes all sessions. The app keeps at least one passkey; after recovery, add the replacement before deleting the old one.

Exports require a fresh passkey verification and contain **unencrypted TOTP secrets** as authenticator links. Store the file in an encrypted password manager or encrypted offline storage. To restore individual entries, paste each link through **Add account**. Bulk JSON restore is not included.

## Security model

Encryption protects stored account records. The Worker holds the encryption key and decrypts records to generate codes: this is not end-to-end encryption. Anyone with control of the deployed Worker or its secrets can access the TOTP seeds. Passkey and SSH public keys are stored unencrypted, and session/challenge tokens are stored by SHA-256 hash.

Recovery uses OpenSSH's SSHSIG format, with the `passkey-vault` namespace, SHA-256/SHA-512 message hashes, and domain-bound, expiring challenges. Legacy RSA-SHA1 signatures are rejected. Signing happens locally with `ssh-keygen`; only a public key and signature reach the app. Revoked keys are checked again at verification time.

Never submit a private SSH key to the app. No analytics, third-party browser scripts, or request logging are enabled. Avoid enabling request body logging for authentication, TOTP enrollment, or export routes.

## Validation

```sh
npm run check
npm run build
npm test
npm audit
npx wrangler deploy --dry-run
```

The tests run in Cloudflare's Workers runtime. QR tests decode generated normal and inverted images, reject unsupported codes, verify camera cleanup and permission-denial handling, and prevent late results from filling a closed dialog. They cover all RFC 6238 test vectors, encryption integrity, real OpenSSH signature fixtures, origin/auth checks, setup gating, session expiry, rate limits, key revocation, and recovery challenge replay. Browser QA additionally exercised virtual-passkey registration/login, TOTP add/import/copy, SSH public-key registration, real `ssh-keygen` recovery, and mobile layout. The production deployment has passed unauthenticated API and origin checks; first registration with your real passkey remains a user setup step.

Useful references: [SimpleWebAuthn](https://simplewebauthn.dev/docs/packages/server), [OpenSSH SSHSIG protocol](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig), [Cloudflare Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/).

## Password manager and Bitwarden import

The vault also stores login names, usernames, passwords, URLs, and notes. Use **Add login** to create an entry, optionally generate a 24-character random password, then save it. Search matches login names, usernames, and URLs alongside authenticator accounts. **Edit / reveal** opens the details; **Copy password** copies a password without placing it on the card. Login lists never include passwords or notes. Reading, saving, deleting, importing, and exporting passwords require authentication within the past two minutes, with the existing passkey confirmation flow when needed. Locking clears loaded details and import data from the UI. Copied secrets remain in your system clipboard; clear it after use.

Choose **Import Bitwarden** and select an **unencrypted JSON** export made by Bitwarden. Preview the login count and names, then confirm import. Names, usernames, passwords, URLs, and notes are retained; cards, identities, and secure notes are skipped. Folders, collections, custom fields, attachments, password history, saved passkeys, URI match rules, and TOTP seeds are not imported. Import reports entries containing omitted extra fields. Import validation completes before any records are written, and the encrypted records are committed in one storage transaction. Limits: 500 stored logins, 500 logins per import, 2000 source items, and a file smaller than 1.9 MB in the UI. Repeating an import adds duplicates; it does not merge or overwrite existing entries. Encrypted JSON and CSV exports are unsupported.

The offline export now includes password entries as well as TOTP setup links. Both the Bitwarden source file and the vault export contain plaintext secrets; keep them in encrypted storage and remove temporary copies after use. Password records use AES-256-GCM with their storage IDs as associated data, under the existing `VAULT_KEY`. This uses the same server-held key model as TOTP storage: it is not end-to-end encryption, and control of the Worker or its secrets permits decryption. No browser extension or autofill is included.

## Automatic deployment with GitHub Actions

The deployment workflow runs type checks, the build, and tests, then deploys to Cloudflare on every push to `main`. You can also run **Deploy to Cloudflare** manually from GitHub's Actions tab on `main`.

In GitHub **Settings → Secrets and variables → Actions**, configure:

- Repository secret `CLOUDFLARE_API_TOKEN`: a Cloudflare API token using the **Edit Cloudflare Workers** template, scoped to your account.
- Repository variable `CLOUDFLARE_ACCOUNT_ID`: your Cloudflare account ID.
- Repository variable `APP_ORIGIN`: your permanent HTTPS origin, without a trailing slash, such as `https://passkey-vault.YOUR-SUBDOMAIN.workers.dev`.

The workflow passes `APP_ORIGIN` to Wrangler, overriding the local default without editing `wrangler.jsonc`. Choose the permanent hostname before registering production passkeys. For a custom domain, configure its routing in Cloudflare separately.

Configure `VAULT_KEY` and `SETUP_KEY` directly as Worker secrets using the deployment instructions above. They are not GitHub Actions secrets, and deployments preserve their existing values. For a first deployment, add those secrets before registering your passkey; the API returns 503 until they are configured. Keep the production vault key stable and backed up.
