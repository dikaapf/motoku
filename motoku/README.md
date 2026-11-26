# Motoku OSINT

OSINT information-gathering toolkit built with Flask. Seventeen modules covering
phone, IP, username (WhatsMyName), email intelligence, domain (RDAP/WHOIS), DNS,
DNS security grading, HTTP security headers & TLS, subdomain enumeration, port
scanning, technology detection, dorks, people search, CCTV discovery, and flight
tracking — all reachable from one unified search bar.

## Requirements

- Python 3.13+
- pip

## Local setup

```bash
cd motoku
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # adjust values
python app.py
```

Open <http://127.0.0.1:5000>.

## Configuration

All settings are environment variables (see `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `MOTOKU_SECRET_KEY` | `dev-only-change-me` | Flask session secret. **Change in production.** |
| `MOTOKU_HOST` | `127.0.0.1` | Bind address. Use `0.0.0.0` inside Docker. |
| `MOTOKU_PORT` | `5000` | Bind port. |
| `MOTOKU_DEBUG` | `0` | Set to `1` only for local development. |
| `MOTOKU_AUTH_USER` | empty | Enables HTTP Basic auth when set together with the password. |
| `MOTOKU_AUTH_PASSWORD` | empty | Basic auth password. |
| `MOTOKU_HTTP_TIMEOUT` | `10` | Outbound HTTP timeout (seconds). |
| `MOTOKU_DB_PATH` | `data/motoku.db` | SQLite database file. |
| `MOTOKU_CSRF_ENABLED` | `1` | CSRF protection on POST/PUT/PATCH/DELETE. |
| `MOTOKU_RATE_LIMIT_ENABLED` | `1` | Enable per-client rate limiting. |
| `MOTOKU_RATE_LIMIT_REQUESTS` | `120` | Requests allowed per window. |
| `MOTOKU_RATE_LIMIT_WINDOW` | `60` | Window size in seconds. |
| `MOTOKU_REDIS_URL` | empty | Redis URL for the shared result cache and quota counters. Empty = in-memory cache. |
| `MOTOKU_HIBP_API_KEY` | empty | Have I Been Pwned API key; enables breach lookups in Email Intelligence. |
| `MOTOKU_DNS_DOH_FALLBACK` | `1` | Retry over DNS-over-HTTPS when the system resolver returns nothing. |
| `MOTOKU_DOH_URL` | Cloudflare | DoH JSON endpoint used for the fallback and DNSSEC validation. |

Debug mode is disabled by default, and the app binds to localhost unless
configured otherwise.

## Docker

```bash
cd motoku
docker compose up --build
```

The `./data` directory is mounted into the container so camera and tracking
data persist across restarts. Compose also starts a Redis container that backs
the result cache and daily provider quotas.

## Tests and lint

```bash
pip install -r requirements-dev.txt
pytest
ruff check .
```

CI runs the same commands on every push and pull request.

## Project layout

```
app.py               Flask routes and app configuration
config.py            Environment-based configuration
db.py                SQLite persistence + legacy JSON migration
rate_limit.py        In-memory sliding-window rate limiter
services/
  cache.py           Redis / in-memory TTL cache
  detect.py          Input-type detection for the unified search bar
  resolver.py        DNS resolver with DNS-over-HTTPS fallback
  providers/         Provider abstraction (cache, quota, API keys) + registry
tools/               One module per OSINT capability
templates/           Jinja2 templates
static/              CSS/JS assets
data/                Datasets (CCTV, WhatsMyName, disposable domains) + SQLite
tests/               Pytest smoke and unit tests
```

## Status dashboard

`/status` shows the active configuration, record counts, rate-limit counters,
the cache backend, dataset versions, and every registered provider with its
API-key state, daily quota (used/remaining), calls, cache hits, and errors.
Quotas are enforced locally so the app stays under each provider's limits;
cache hits do not consume quota.

## Adding a provider

Declare it once in `services/providers/registry.py`:

```python
SHODAN = register('shodan', ttl=6 * 3600, daily_quota=100,
                  key_env='MOTOKU_SHODAN_API_KEY', description='Shodan host lookup')
```

Then wrap the outbound call: `SHODAN.fetch(cache_key, lambda: fetch_json(...))`.
Caching, quota enforcement, missing-key errors and usage accounting are handled
by `Provider.fetch`.

## Notes on the S0 hardening pass

- Fixed the technology detector for python-Wappalyzer 0.3.x.
- Fixed the DNS module: SPF is parsed from TXT, plus DMARC, DKIM, and DNSSEC.
- Made Sherlock/Instaloader imports lazy with actionable error messages.
- Switched IP lookups to HTTPS and added explicit timeouts.
- Relabelled the Wikipedia enrichment results so they are not presented as
  general web search results.
- Added environment-based config, security headers, optional Basic auth,
  Docker, `.gitignore`, pytest, and CI.
- Untracked `__pycache__` and personal `data/tracking.json` from git.
- Added CSRF protection for all state-changing forms (the public location
  beacon endpoint is exempt).
- Migrated tracking records and CCTV cameras from JSON files to SQLite, with a
  one-time automatic import of the legacy files.
- Added per-client rate limiting and a `/status` page with provider usage
  counters.

## S1 — Core OSINT upgrade

- **Unified search** (navbar + home): detects email, IP, URL, domain, phone,
  username or person name and routes to the matching tools (`/search?q=`,
  `/api/detect?q=`). Tool pages accept `?q=…&auto=1` to prefill and run.
- **Username**: WhatsMyName dataset (~650 sites) checked in parallel with
  per-site "exists"/"missing" markers; category filter, optional NSFW, and an
  in-app dataset updater.
- **Email intelligence**: syntax, MX (with implicit-MX fallback), optional SMTP
  RCPT probe with catch-all detection, disposable (~10k domains), free-provider
  and role-account detection, HIBP breaches, Gravatar, EmailRep, risk score.
- **DNS security analyzer** (`/dns-security`): SPF (qualifier, lookup count),
  DMARC (policy, pct, rua, sp), DKIM selectors and key size, DNSSEC (DS/DNSKEY
  + validating resolver), MTA-STS policy, TLS-RPT, CAA, BIMI — graded A+…F
  with recommendations.
- **Headers & TLS** (`/web-security`): grades HSTS, CSP, XFO, XCTO,
  Referrer-Policy, Permissions-Policy, COOP/CORP, cookie flags, version leaks;
  certificate subject/issuer/SAN/expiry/protocol/cipher, including invalid certs.
- **Domain**: RDAP via rdap.org bootstrap (registrar, IANA ID, abuse contact,
  DNSSEC, status), automatic WHOIS fallback.
- **Provider layer**: cache (Redis or memory), daily quotas, API-key gating and
  usage accounting shared by all new modules.
- **UI**: result cards with copy buttons and JSON/CSV export on the new pages
  and DNS.

Datasets: [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) (CC BY-SA
4.0) and [disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains) (CC0).
