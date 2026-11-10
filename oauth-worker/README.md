# OAuth Worker

GitHub Pages is static: it cannot keep an OAuth App client secret and cannot
call the GitHub token endpoint directly because that endpoint does not send
CORS headers. This Worker performs the one request that needs the secret.

It accepts `POST /` with:

```json
{ "code": "temporary-code", "redirect_uri": "https://owner.github.io/zone-ion/" }
```

and returns:

```json
{ "access_token": "...", "token_type": "bearer", "scope": "public_repo" }
```

The Worker checks `Origin` and the exact `redirect_uri` against the values in
`wrangler.toml`. It does not log or store tokens.

## Deploy

1. Install Wrangler: `npm install -g wrangler`.
2. Edit `wrangler.toml`:
   - `ALLOWED_ORIGINS`: your Pages origin, for example
     `https://owner.github.io`.
   - `ALLOWED_REDIRECT_URIS`: the exact callback URL, for example
     `https://owner.github.io/zone-ion/`.
3. Create the Worker and secrets:

   ```bash
   cd oauth-worker
   wrangler login
   wrangler deploy
   wrangler secret put GITHUB_CLIENT_ID
   wrangler secret put GITHUB_CLIENT_SECRET
   ```

4. Copy the printed `https://ion-oauth.<subdomain>.workers.dev` URL into
   `web/config.js` as `oauthWorkerUrl`.

## Test locally

```bash
wrangler dev
```

Then send a request with an allowed `Origin`:

```bash
curl -i http://127.0.0.1:8787/healthz -H "Origin: https://owner.github.io"
```

A real code exchange needs valid GitHub OAuth credentials. Keep the client
secret in Wrangler secrets, never in `wrangler.toml` or the static site.
