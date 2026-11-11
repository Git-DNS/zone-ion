# The `.ion` root zone

`.ion` is a public root zone for GitDNS. It is not a replacement for ICANN
domains: it is a separate namespace that a GitDNS resolver can serve from git.
Every domain is a signed TOML file. Every change is a commit. The website in
`web/` lets a GitHub user register a name, manage records, and keep the private
signing key in their own browser.

The repository is designed to be published as a standalone GitHub repository,
for example `https://github.com/OWNER/zone-ion`.

## What is in this repository

```
zone.toml                       zone manifest (SOA, NS, allowed record types)
domains/_records.toml           zone apex, maintained by the maintainers
domains/<name>/_records.toml    registered domains and subdomains
registry/registrations.json     public registration ledger (created by the bot)
registry/reserved.json          names that cannot be registered
scripts/zone_admin.py           validator, ledger writer and commit bot
scripts/requirements.txt        Python dependencies
web/                            static registration and management site
oauth-worker/                   Cloudflare Worker for GitHub OAuth code exchange
tests/                          Python and JavaScript compatibility tests
.github/workflows/              registration, validation and Pages workflows
```

## Rules

1. **GitHub sign-in is required.** The issue author is the GitHub account kept
   in the ledger. A valid signature alone cannot register or update a name.
2. **One second-level domain per account every 48 hours.** Subdomains are
   unlimited. Updates do not start a new cooldown.
3. **A subdomain needs an owned parent.** The same GitHub account and the same
   owner key must own the second-level domain.
4. **Non-apex files must be signed.** The bot rebuilds the canonical payload and
   verifies the ed25519 signature before writing anything.
5. **One key belongs to one GitHub account.** Importing a key that is already
   linked to another account is rejected.
6. **Reserved names are rejected.** See `registry/reserved.json`.
7. **The apex is maintainer-only.** Use a pull request, not the public site.

The 48-hour rule is enforced by the bot from the ledger timestamps, not by the
browser. The browser check is only a convenience.

## How registration works

```
Browser                     GitHub                      GitHub Actions
-------                     ------                      --------------
GitHub OAuth  ----------->  authorize
      |  <----------------- access token (Worker exchange)
      |
create key (localStorage)
sign canonical JSON
open issue with a signed TOML block  ---->  issue #123
                                             registration.yml
                                               |
                                               v
                                         scripts/zone_admin.py
                                           verify signature
                                           check 48-hour rule
                                           check parent ownership
                                           write domain file + ledger
                                           git commit && git push
                                           comment on and close #123
```

The site never sends the private key anywhere. The issue contains only the
public key, the records and the signature.

## Publish the repository

1. Create a new **public** GitHub repository named `zone-ion`. Do not make it a
   subdirectory of another repository.
2. Push the contents of this folder as the first commit:

   ```bash
   cd zone-ion
   git init
   git add .
   git commit -m "Initial .ion zone"
   git branch -M main
   git remote add origin https://github.com/OWNER/zone-ion.git
   git push -u origin main
   ```

3. In **Settings → Actions → General**, allow workflows to read and write
   repository contents, or use the optional token described below.
4. In **Settings → Pages**, set **Source** to **GitHub Actions**. The
   `pages.yml` workflow publishes the `web/` folder.
5. Edit `web/config.js`:

   ```js
   window.ION_CONFIG = {
     zoneName: "ion",
     zoneRepo: "OWNER/zone-ion",
     branch: "main",
     oauthClientId: "Iv1.xxxxxxxxxxxx",
     oauthWorkerUrl: "https://ion-oauth.example.workers.dev",
     sourceRepo: "OWNER/GitDNS",
   };
   ```

6. Create a GitHub OAuth App at
   **Settings → Developer settings → OAuth Apps → New OAuth App**:
   - Homepage URL: `https://OWNER.github.io/zone-ion/`
   - Authorization callback URL: `https://OWNER.github.io/zone-ion/`
     (the exact URL, including the trailing slash)
7. Deploy the OAuth Worker by following `oauth-worker/README.md`, then put its
   URL and the client ID in `web/config.js`.
8. Commit and push `web/config.js`. The `pages` workflow deploys the site.

If the repository is served from a user or organization page
(`https://OWNER.github.io/`) instead of a project path, use that URL for both
OAuth values and for `ALLOWED_ORIGINS` in the Worker.

### Before you go live

`zone.toml` advertises `ns = ["ns1.ion", "ns2.ion"]`, but those names are only
reserved placeholders until you publish them. A resolver cannot reach the zone
without working name-server addresses:

1. Decide which hosts answer for the zone and keep a **maintainer key** offline.
   It is used only for the apex and infrastructure files and is never loaded by
   the website.
2. Add signed `domains/ns1/_records.toml` and `domains/ns2/_records.toml` with
   the real `A`/`AAAA` (glue) addresses, signed by that maintainer key. Because
   they are maintainer infrastructure, either add them through a protected pull
   request or allow the maintainer key in the ledger without the public site.
3. Update the apex `domains/_records.toml` if you also want `NS` records there,
   and bump the SOA serial.
4. Run `python scripts/zone_admin.py verify-zone --root .` and
   `gitdns verify-zone --dir . --strict` before the first public announcement.
5. Point your GitDNS resolver (or the desktop app) at the repository URL and
   confirm that `example.ion` resolves.

Until this is done the registry and the website work, but the zone has no
reachable name servers. Keep the maintainer key out of `main`, out of the
browser, and out of any workflow secret that the registration bot can read.

### Protecting `main`

If `main` is protected against direct pushes, the default `GITHUB_TOKEN`
cannot commit. Create a fine-grained personal access token with **Contents:
read and write** and **Issues: read and write**, then add it as the repository
secret `REGISTRY_TOKEN`. The registration workflow uses that secret when it is
present:

```yaml
token: ${{ secrets.REGISTRY_TOKEN || secrets.GITHUB_TOKEN }}
```

Do not require pull requests for the bot path, or allow the bot identity to
bypass the rule.

## Local development

Requirements: Python 3.11+, Node 18+, and `cryptography`.

```bash
pip install -r scripts/requirements.txt

# Check every signature and the ledger
python scripts/zone_admin.py verify-zone --root .

# Python tests (validator, cooldown, ownership, idempotency)
python -m unittest discover -s tests -p "test_*.py"

# JavaScript tests (canonical JSON, signatures, GitHub Pages preset)
node --test tests/canonical.test.mjs tests/pages.test.mjs
```

To try the static site without GitHub:

```bash
cd web
python -m http.server 8000
```

The public zone data loads from `raw.githubusercontent.com`. Sign-in needs the
deployed OAuth Worker and an OAuth App whose callback URL is
`http://localhost:8000/`. Add `http://localhost:8000` to the Worker's
`ALLOWED_ORIGINS` and `http://localhost:8000/` to `ALLOWED_REDIRECT_URIS`
while testing locally.

You can validate one issue body without writing:

```bash
python scripts/zone_admin.py apply --root . \
  --issue-number 1 --user alice --body-file issue.md --dry-run
```

### Optional: register with the GitDNS CLI

The same format can be created offline:

```bash
gitdns keygen --out alice
gitdns register --zone-dir . --name shop --key alice.key --a 192.0.2.10
gitdns verify-zone --dir . --strict
```

Commit the generated `domains/shop/_records.toml` and open a pull request. The
private key (`alice.key`) must never be committed. The website does the same
operation in JavaScript.

## Record format

`domains/<name>/_records.toml` contains one domain name relative to the zone,
the owner public key, timestamps, records and a signature:

```toml
schema = 1
name = "shop"
owner = "ed25519:..."
created = "2026-05-01T12:00:00Z"
updated = "2026-05-01T12:00:00Z"

[[records]]
type = "A"
value = "192.0.2.10"

[[records]]
type = "MX"
value = "mail.example.com."
priority = 10

[signature]
key = "ed25519:..."
value = "base64url-signature"
signed_at = "2026-05-01T12:00:00Z"
```

Supported types: `A`, `AAAA`, `CNAME`, `TXT`, `MX`, `NS`, `SRV`, `CAA`, `PTR`,
`REDIRECT`. `CNAME` and `REDIRECT` cannot be combined with other records for the
same name. TTL is limited to 7 days. See `docs/ZONE_FORMAT.md` in the GitDNS
source for the full format.

### Redirect records

`REDIRECT` is not a DNS record type on the wire. A name with a `REDIRECT`
record resolves to the address of the built-in redirect listener, and the
listener answers a normal HTTP request with `301 Moved Permanently` and the
stored URL:

```toml
[[records]]
type = "REDIRECT"
value = "https://example.com/"
```

The target must be an absolute `http://` or `https://` URL. A redirect cannot
share a name with other records, and wildcard names are not supported.

Turn the listener on in **Settings → Redirects** in the desktop app. The default
is `0.0.0.0:80`; binding a low port may need administrator (Windows) or root
(Linux/macOS) rights. If you change the port, open `http://name:port/`: a browser
does not try other ports. The **answer address** is what DNS clients receive, so
it must be reachable from the browser: `127.0.0.1` works only when the browser
and GitDNS run on the same computer, and the LAN address is needed for other
devices. The listener is HTTP only; see the next section for why.

### GitHub Pages shortcut

The record editor has a **GitHub Pages** entry. It is an editor preset, not a
DNS type: it creates one `REDIRECT` record to
`https://<owner>.github.io/<repository>/`, or to
`https://<owner>.github.io/` when the repository is `<owner>.github.io`.

GitHub Pages cannot serve a `.ion` name over HTTPS. GitHub and Let's Encrypt
cannot validate a name that only resolves inside GitDNS, so a custom domain in
the repository settings ends with **503 Service Unavailable** once HTTPS is
used. Plain HTTP can still load the site, but browsers and GitHub prefer HTTPS.

The redirect avoids the problem: `http://shop.ion/` is answered by GitDNS with
a 301 to the github.io address, where GitHub's own certificate is valid. Keep
the custom domain field **empty** in **Settings → Pages** of the repository. If
it is set to the `.ion` name, GitHub redirects the github.io address back to
`.ion` and the browser loops.

Enter a repository name (`my-site`), `owner/repository`, or a github.com URL.
The repository must belong to the same GitHub account as the domain. Add the
shortcut for every host you want, including `www.<name>`.

A/AAAA records still accept several addresses in one entry:

```toml
[[records]]
type = "A"
values = ["185.199.108.153", "185.199.109.153", "185.199.110.153", "185.199.111.153"]
```

### Canonical payload

The signature is not made over the TOML text. It is made over compact JSON with
a fixed field order:

```json
{"schema":1,"zone":"ion","name":"shop","owner":"ed25519:...","created":"...","updated":"...","records":[...]}
```

Records are uppercased and sorted by their own compact JSON. The same bytes are
produced by:

- `crates/gitdns-core/src/record.rs` (Rust resolver and CLI),
- `scripts/zone_admin.py` (bot validation),
- `web/zone.js` (browser signing).

`tests/fixtures/canonical-shop.json` and the JavaScript test prove that all
three agree.

## Ledger

`registry/registrations.json` is the public source of truth for ownership,
cooldowns and the personal cabinet:

```json
{
  "version": 1,
  "zone": "ion",
  "registrations": [
    {
      "domain": "shop",
      "fqdn": "shop.ion",
      "kind": "second_level",
      "user": "alice",
      "owner": "ed25519:...",
      "created": "2026-05-01T12:00:00Z",
      "registered_at": "2026-05-01T12:00:00Z",
      "updated_at": "2026-05-01T12:00:00Z",
      "issue": 123,
      "records": [{ "type": "A", "value": "192.0.2.10" }]
    }
  ]
}
```

Only entries with `"kind": "second_level"` count toward the 48-hour limit.
`registered_at` is set by the bot and is never taken from the issue text.

## Security model

- The private key is generated in the browser and stored in `localStorage`
  under `ion.identity.v1`, one identity per GitHub login. Export it if you want
  a backup. Losing it means losing the ability to update your domains.
- The GitHub token is kept in `sessionStorage`, sent only to `api.github.com`,
  and disappears when the tab session ends. The OAuth scope is `public_repo`.
- The OAuth client secret exists only in Cloudflare Worker secrets. The Worker
  checks the exact callback URL and allowed origins.
- The bot treats the **issue author** as the GitHub identity. It does not trust
  a user name written in the issue body.
- Every write is validated against the canonical payload and the ledger. A
  tampered file is rejected before it reaches `main`.
- The 48-hour limit, parent ownership and reserved names are enforced server
  side. Editing an issue can fix a request but cannot reset its original
  `registered_at`.
- The ledger and every domain file are public. Do not put private data in TXT
  records.

Limits that are outside this repository's control:

- GitHub accounts are free, so the 48-hour rule is per account, not per person.
  Maintainers can add stricter checks or moderation if needed.
- A compromised browser profile or exported key file lets an attacker sign as
  the owner. Keep the export offline.
- A maintainer with repository write access can always edit `main`. Use branch
  protection and review for the maintainer path if that matters to your users.

## Workflows

- `registration.yml` — runs on `issues: opened/edited/reopened`, every six
  hours, and manually. Applies the triggering issue and then sweeps the other
  open registration issues, one commit per sweep. Serialized with a
  concurrency group.
- `validate-zone.yml` — verifies all files and the ledger, runs the Python and
  JavaScript tests, and rejects committed private keys.
- `pages.yml` — publishes `web/` when the site changes. Zone data is read live
  from the repository, so bot commits do not rebuild Pages.

### Registration capacity

One runner is enough for a normal launch. GitHub cancels all but one pending
run in a concurrency group, so a burst of issues can cancel queued runs. Every
run also sweeps, which means the run that wins applies the whole queue instead
of only its own issue. A sweep commits and pushes once for all of its changes.

Practical limits for a single runner:

- Registrations are applied one after another. One run costs roughly 10–20
  seconds: checkout, pip install, validation and one push.
- The sweep reads up to 1000 open issues. Commenting and closing costs two
  GitHub calls per issue; the secondary rate limit of about 80 content writes
  per minute caps a burst at roughly 30–40 registrations per minute.
- The 48-hour rule keeps second-level registrations per GitHub account low, so
  bursts are mostly subdomains, which have no limit.
- A failed issue does not block the rest: validation errors are commented on
  the issue and skipped, and the sweep continues.

Add workers only when you need more than a few hundred registrations per hour.
The natural split is one repository per root zone, because each repository has
its own concurrency group and runner. For a single very large zone, shard the
workflow by first label and give each shard its own ledger and concurrency
group.

## Troubleshooting

**The site says "Setup needed".**
`web/config.js` still contains `OWNER` or `SETUP` values. Fill in the repository,
OAuth client ID and Worker URL, then push.

**GitHub sign-in says "redirect_uri is not allowed".**
The Worker's `ALLOWED_REDIRECT_URIS` must contain the exact page URL, including
the trailing slash. It must match the OAuth App callback URL.

**The issue exists but the domain is not in the ledger.**
Open the workflow run. A failed signature, cooldown or ownership check is
reported as a comment on the issue. Edit the issue after fixing the problem.

**"This domain belongs to a different owner key."**
The browser identity was replaced. Import the key that signed the original
registration, or register a new domain.

**The 48-hour cooldown looks wrong.**
The ledger is authoritative. `registered_at` is set when the bot commits, not
when the issue is opened.

## License

This zone repository contains configuration and tooling. Add the license that
fits your project before publishing. The GitDNS source repository has its own
license.
