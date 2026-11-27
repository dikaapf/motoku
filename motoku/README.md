# Motoku OSINT

OSINT information-gathering toolkit built with Flask. Twenty modules covering
phone, IP, username (WhatsMyName), email intelligence, domain (RDAP/WHOIS), DNS,
DNS security grading, HTTP security headers & TLS, multi-source subdomain
enumeration with takeover detection, nmap port scanning, TLS/CT scanning,
Wayback/urlscan/favicon pivots, technology detection, dorks, people search, CCTV
discovery, and flight tracking — plus a one-click domain recon pipeline that
runs in the background. Everything is reachable from one unified search bar.

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
| `MOTOKU_JOB_BACKEND` | `thread` | `thread` (in-process pool), `rq` (Redis Queue + worker), or `inline` (synchronous; tests). |
| `MOTOKU_JOB_WORKERS` | `4` | Thread-pool size for the `thread` backend. |
| `MOTOKU_URLSCAN_API_KEY` | empty | Optional urlscan.io key (higher search limits). |
| `MOTOKU_OTX_API_KEY` | empty | Optional AlienVault OTX key. |
| `MOTOKU_CERTSPOTTER_API_KEY` | empty | Optional CertSpotter key. |
| `MOTOKU_CHROMIUM_PATH` | auto | Chromium binary for screenshots (auto-detected). |
| `MOTOKU_NMAP_PATH` | `nmap` | nmap binary; port scans fall back to TCP connect when absent. |

Threat-intel API keys (all optional; every source without a key is shown as
"butuh key" and skipped): `MOTOKU_SHODAN_API_KEY`, `MOTOKU_CENSYS_API_ID` +
`MOTOKU_CENSYS_API_SECRET`, `MOTOKU_FOFA_API_KEY`, `MOTOKU_NETLAS_API_KEY`,
`MOTOKU_VT_API_KEY`, `MOTOKU_ABUSEIPDB_API_KEY`, `MOTOKU_GREYNOISE_API_KEY`,
`MOTOKU_IPINFO_TOKEN`, `MOTOKU_ABUSECH_API_KEY` (URLhaus + MalwareBazaar),
`MOTOKU_PHISHTANK_API_KEY`, `MOTOKU_GSB_API_KEY`, `MOTOKU_NVD_API_KEY`,
`MOTOKU_GITHUB_TOKEN`, `MOTOKU_FIRMS_MAP_KEY`, `MOTOKU_OPENCORPORATES_TOKEN`,
`MOTOKU_REDDIT_CLIENT_ID` + `MOTOKU_REDDIT_CLIENT_SECRET`. Free sources that need no key: Shodan InternetDB,
Shodan CVEDB, FIRST EPSS, CISA KEV, RIPEstat, IPinfo (limited), GreyNoise
community, OTX, PhishTank.

Debug mode is disabled by default, and the app binds to localhost unless
configured otherwise.

## Docker

```bash
cd motoku
docker compose up --build
```

The `./data` directory is mounted into the container so camera and tracking
data persist across restarts. Compose also starts Redis (result cache, daily
provider quotas, job queue) and an `rq` worker that runs recon, subdomain,
port-scan and username jobs. The image ships nmap and Chromium.

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
cli.py               Command-line client for the REST API (+ local watch-run)
extension/           Browser extension (Manifest V3, Chrome/Edge/Brave/Firefox)
routes/              Blueprints: cases, watchlist, settings, REST API v1
services/
  cache.py           Redis / in-memory TTL cache
  detect.py          Input-type detection for the unified search bar
  http.py            Retry/backoff helper for flaky public sources
  jobs.py            Background job queue (thread / RQ), state in SQLite
  job_handlers.py    Job registrations (recon, subdomain, portscan, username)
  recon.py           One-click domain recon pipeline
  casedb.py          Cases, entities, relations, findings, notes, attachments, custody
  importer.py        Tool result → entities/relations/findings (case auto-fill)
  report.py          Markdown / JSON / CSV-zip / HTML / PDF reports
  watch.py           Watchlist checks, diff → alerts, webhook/email, scheduler
  api_tokens.py      Hashed REST API tokens with scopes
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

## S2 — Infra recon

- **Background jobs** (`services/jobs.py`): long scans run as jobs whose state,
  progress, log and result live in SQLite. Pages stream progress over
  Server-Sent Events (`/api/jobs/<id>/events`) and reload when done. `/jobs`
  lists recent jobs. Backends: in-process threads (default) or RQ + Redis.
- **Subdomains**: crt.sh, CertSpotter, AlienVault OTX, HackerTarget + DNS brute
  force, merged per source, resolved concurrently (A/AAAA/CNAME), with wildcard
  DNS detection and filtering.
- **Takeover detection**: CNAME fingerprints for ~25 services (S3, GitHub Pages,
  Heroku, Azure, Shopify, Netlify, …) confirmed by NXDOMAIN or service error page.
- **HTTP probe**: status, title, server, redirects, favicon; screenshots through
  Playwright when installed, otherwise headless Chromium.
- **Port scan**: nmap `-sT -sV` (no root) with XML parsing, CPEs and per-port
  risk rating; TCP-connect + banner fallback; custom port lists/ranges.
- **TLS scan** (`/tls`): TLS 1.0–1.3 support, cipher, certificate, grade, and
  Certificate Transparency history from crt.sh.
- **Archive** (`/archive`): Wayback CDX with "interesting URL" flags, urlscan.io
  search, Shodan-compatible favicon mmh3 hash.
- **Recon pipeline** (`/recon`): one domain → RDAP, DNS security, subdomains,
  takeover, HTTP probe, screenshots, TLS/CT, port scan, archive — summarised as
  prioritised findings, exportable as JSON/CSV. Failing stages are recorded and
  the pipeline continues.

Only scan assets you own or are authorised to test.

## S3 — Threat intel & enrichment

- **Threat intel** (`/intel`): one indicator (IP, domain, URL, MD5/SHA1/SHA256)
  checked in parallel against Shodan, InternetDB, Censys, FOFA, Netlas,
  VirusTotal, AbuseIPDB, GreyNoise, IPinfo, RIPEstat (+RPKI), URLhaus, PhishTank,
  Google Safe Browsing, OTX and MalwareBazaar. Results are normalised to a
  verdict (malicious / suspicious / clean / unknown) and aggregated.
- **CVE mapping** (`/cve`): CVE ID, CPE or "product version" → CVEs with CVSS,
  EPSS (FIRST) and CISA KEV, prioritised P1–P4. nmap CPEs such as
  `openssh:6.6.1p1` fall back to `6.6.1` → `6.6` when the CPE dictionary lacks
  the exact version.
- **Typosquatting** (`/typosquat`): dnstwist-style permutation engine (13
  techniques incl. IDN homoglyphs and bitsquatting), concurrent resolution,
  MX-aware risk rating, plus IDN homograph analysis (mixed scripts, confusables).
- **Cloud & leaks** (`/cloud`): S3 (region-aware), GCS and Azure Blob bucket
  discovery with anonymous-listing check (object names only); GitHub code
  search for the domain with secret classification and masking.
- **Provider dashboard** (`/providers`): every provider grouped by category with
  key state, local daily quota, provider-reported quota (AbuseIPDB headers,
  Shodan/VirusTotal/GitHub account endpoints), cache-hit ratio and a 14-day
  usage chart.
- **Recon enrichment**: the `/recon` pipeline now adds threat intel for the
  domain and its IPs, CVE mapping from port-scan CPEs and InternetDB, typosquats
  and cloud buckets, all feeding the prioritised findings.

## S4 — People, image & geo

- **Phone** (`/phone`): libphonenumber + Indonesian prefix → issuing operator
  (MNP caveat), all number formats, footprint search links and manual messenger
  links (wa.me, t.me). Messenger registration is deliberately *not* probed
  automatically (needs unofficial automation and enables stalking).
- **Image forensics** (`/image`): upload or URL; EXIF + GPS (reverse-geocoded),
  full exiftool metadata, MD5/SHA1/SHA256 + aHash/dHash, editing/tampering hints,
  Tesseract OCR (eng+ind) and reverse-image-search links. Uploads stay in memory.
- **Corporate & academic** (`/corporate`): GLEIF LEI, OpenCorporates (token),
  ORCID, OpenAlex, plus Indonesian registries without APIs (AHU, OSS, IDX,
  putusan MA, SINTA).
- **Geo** (`/geo`): decimal/DMS/Google-Maps-URL parsing, Nominatim (1 req/s),
  Overpass POIs with mirror fallback, NASA FIRMS hotspots (MAP_KEY), map and
  satellite links (Copernicus, Sentinel Hub, Worldview, Mapillary), and a NOAA
  solar-position calculator: sun azimuth/elevation, shadow direction/length,
  sunrise/sunset and an hourly table for chronolocation — drawn on a Leaflet map.
- **Social profiles** (`/social`): GitHub, Reddit (OAuth app), Mastodon
  (instance lookup), Bluesky, Telegram (public page) and TikTok (best-effort),
  with per-platform pivots and a same-name ≠ same-person warning.
- **Unified search** now recognises coordinates, image URLs and LEI codes, and
  routes usernames to social profiles and names to corporate/academic search.

## S5 — Case management & reporting

- **Cases** (`/cases`): case → entities (typed, de-duplicated) → relations →
  findings (severity + status), notes, attachments, tags and a timeline.
- **Auto-fill**: every tool result has a **Case** button that extracts entities,
  relations and findings into a case (per-tool extractors + a generic fallback).
  Finished jobs can be imported too, and `/recon` can write straight into a new
  or existing case.
- **Entity graph & timeline**: vis-network graph (low-priority CVEs folded) and
  vis-timeline of every case event.
- **Chain of custody**: append-only SHA-256 hash chain over every change,
  attachment access and report export; `/cases/<id>/custody` verifies it.
  Attachments are stored by SHA-256 and re-verified on download.
- **Reports**: Markdown, JSON, CSV zip (entities/findings/relations/timeline/
  custody), printable HTML and PDF (headless Chromium). Each export is hashed
  and logged.
- **Watchlist & alerts** (`/watchlist`): domain (DNS, TLS, new subdomains,
  reputation, new typosquats), IP (ports & CVEs), email (breaches), username
  (profiles). First run = baseline; later diffs become alerts (and case
  findings), delivered to Slack/Discord/JSON webhooks or SMTP email. A scheduler
  thread runs due checks (single runner via DB lease); `python cli.py watch-run`
  works from cron instead.
- **REST API v1** (`/api/v1`, docs at `/api/v1/docs`): bearer tokens with
  `read`/`write`/`scan` scopes, managed at `/settings/tokens` (only hashes are
  stored). Tools, jobs, cases, import, reports, watchlist, alerts.
- **CLI** (`cli.py`): `detect`, `tool`, `recon --wait`, `job`, `case …`,
  `watch …`, `alerts`.
- **Browser extension** (`extension/`): context menu (selection/link/image/page
  → Motoku), popup search, add current page to a case, reputation check. Load it
  unpacked from `chrome://extensions` and set server URL + token in Options.

## S6 — Polish & scale

- **i18n ID/EN**: language switch in the navbar (cookie, `?lang=`, or
  `Accept-Language`); interface chrome, menus, home, search, cases, recon and
  onboarding are translated via `translations/en.json`;
  `scripts/i18n_check.py` (also enforced by tests) reports missing strings.
  Tool result details remain in Indonesian.
- **Command palette** (`Ctrl/Cmd+K`) with fuzzy search over tools, cases and a
  "search this target" action; `/` focuses the search box. Navbar mega-menu,
  home page and palette are all generated from `services/catalog.py`.
- **Performance**: per-thread pooled SQLite connections with WAL /
  `synchronous=NORMAL`, indexes for hot queries (small queries ~50× faster),
  gzip for text/JSON responses (home 41 KB → 7.5 KB), static caching, cache
  warm-up, automatic recovery of stuck jobs.
- **Observability**: request logging (text or JSON, `X-Request-ID`),
  `/healthz`, `/readyz`, Prometheus `/metrics` (HTTP counters/latency + DB
  gauges), optional Sentry, Docker `HEALTHCHECK`.
- **Docs & onboarding**: `/welcome` checklist (security, providers, binaries,
  first case/token) with a warning banner for critical misconfiguration, and
  full documentation in [`docs/`](../docs/README.md).
