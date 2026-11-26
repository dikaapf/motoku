# Motoku OSINT — Roadmap

Total effort: ~95 person-days (PD) across ~9.5 sprints (2 minggu per sprint).
Satuan: 1 PD ≈ 6–8 jam efektif. Solo full-time ≈ 4–5 bulan; 2 dev paralel ≈ 2–2,5 bulan.

---

## Fase & Durasi

| Fase | Fokus | Durasi | Effort | Prasyarat |
|---|---|---|---|---|
| **S0** ✅ | Stabilisasi & fondasi | 1 sprint | ~10 PD | — |
| **S1** ✅ | Core OSINT upgrade | 1 sprint | ~13 PD | S0 |
| **S2** ✅ | Infra recon (domain/IP) | 1.5 sprint | ~16.5 PD | S0, S1 |
| **S3** ✅ | Threat intel & enrichment | 1.5 sprint | ~14.5 PD | S2 |
| **S4** ✅ | People, image, geo | 1.5 sprint | ~12.5 PD | S1 |
| **S5** | Case management & report | 2 sprint | ~19.5 PD | S2, S4 |
| **S6** | Polish & scale (opsional) | 1 sprint | ~9 PD | S5 |
| **Total** | | **~9.5 sprint** | **~95 PD** | |

---

## S0 — Stabilisasi & Fondasi (10 PD)

| # | Task | Effort | Prioritas | Deliverable |
|---|---|---|---|---|
| 0.1 | Fix `tech_tool` (Wappalyzer 0.3.1) | 0.5 | P0 | Tech stack berfungsi |
| 0.2 | Fix `deep_username`: pasang sherlock + instaloader | 1 | P0 | Deep username berfungsi |
| 0.3 | Perbaiki `search_tool.fetch_results` / label jadi Wikipedia | 0.5 | P0 | Tidak menyesatkan |
| 0.4 | DNS: hapus tipe SPF, tambah DMARC/DKIM/DNSSEC | 0.5 | P0 | DNS akurat |
| 0.5 | `ip_tool` HTTPS + timeout, bare except → Exception | 0.25 | P1 | Robustness |
| 0.6 | Pin `requirements.txt`, pasang sherlock/instaloader/b4 | 0.5 | P0 | Repo bersih |
| 0.7 | Security: debug=False, .env, CSRF, auth, rate limit | 2 | P0 | App aman |
| 0.8 | Migrasi JSON → SQLite + SQLAlchemy + Alembic | 2 | P0 | Data layer stabil |
| 0.9 | Dockerfile + docker-compose | 1 | P1 | Deploy reproducible |
| 0.10 | pytest smoke test + GitHub Actions CI | 1.5 | P1 | Regression guard |

**DoD S0:** semua 15 tool tidak ada crash, app bisa `docker compose up`, test hijau.

---

## S1 — Core OSINT Upgrade (13 PD)

| # | Task | Effort | Dampak |
|---|---|---|---|
| 1.1 | Unified search bar auto-deteksi tipe input → routing | 1.5 | UX besar |
| 1.2 | Username engine: WhatsMyName (~600 situs) + cek paralel | 2.5 | Akurasi & cakupan naik |
| 1.3 | Email intelligence: HIBP, MX/SMTP, disposable, Gravatar | 2.5 | Modul email nyata |
| 1.4 | DNS security analyzer: SPF, DKIM, DMARC, DNSSEC, MTA-STS | 2 | Nilai tinggi |
| 1.5 | Security headers grader + TLS cert info | 1.5 | Quick win |
| 1.6 | RDAP + fallback WHOIS | 1 | Modernisasi |
| 1.7 | Provider abstraction + Redis cache + quota tracking | 2 | Fondasi modul selanjutnya |
| 1.8 | UI: result card, copy button, export JSON/CSV | 1.5 | Usability |

**DoD S1:** minimal 3 modul baru produksi (username, email, DNS security) + search bar terpadu.

**Status S1 (2026-11-27): selesai.** Semua 8 task terimplementasi dengan test (`tests/test_s1.py`).
Catatan: scan username penuh (~650 situs) ~40 detik — sudah dipindah ke job queue di S2.
Export JSON/CSV baru dipasang di halaman S1 + DNS; halaman lama menyusul saat dipindah ke result card.

---

## S2 — Infra Recon (16.5 PD)

| # | Task | Effort |
|---|---|---|
| 2.1 | Async job queue (RQ/Celery + Redis) + progress via SSE | 3 |
| 2.2 | Subdomain multi-source: crt.sh, CertSpotter, OTX, HackerTarget | 3 |
| 2.3 | Wildcard detection + subdomain takeover detection | 2 |
| 2.4 | HTTP probe: status, title, server, screenshot (Playwright) | 3 |
| 2.5 | Port scan upgrade: nmap/naabu, service version, risk rating | 2.5 |
| 2.6 | TLS/SSL scan + certificate transparency | 1.5 |
| 2.7 | Wayback CDX, URLScan, favicon hash (mmh3) | 1.5 |

**DoD S2:** satu input domain menghasilkan laporan recon lengkap di background job.

**Status S2 (2026-11-27): selesai.** Job queue (thread/RQ) + SSE, recon pipeline `/recon`,
semua 7 task dengan test (`tests/test_s2.py`). Catatan: naabu tidak dipakai (nmap `-sT -sV` +
fallback TCP connect); screenshot memakai Playwright bila terpasang, selain itu Chromium headless.
Scan username kini juga berjalan sebagai job (menutup catatan S1).

---

## S3 — Threat Intel & Enrichment (14.5 PD)

| # | Task | Effort | API |
|---|---|---|---|
| 3.1 | Shodan / Censys / FOFA / Netlas provider | 2.5 | key berbayar |
| 3.2 | VirusTotal, AbuseIPDB, GreyNoise, IPinfo, BGP/RIPEstat | 2.5 | sebagian gratis |
| 3.3 | URLhaus, PhishTank, Google Safe Browsing, OTX, MalwareBazaar | 2 | gratis |
| 3.4 | CVE mapping + EPSS + CISA KEV | 2 | nil defensif |
| 3.5 | Typosquatting (dnstwist) + homograph detection | 1.5 | brand protection |
| 3.6 | Cloud storage finder (S3/GCS/Azure) + GitHub secret scan | 2.5 | pasif |
| 3.7 | Provider quota dashboard | 1.5 | operasional |

**DoD S3:** hasil recon diperkaya reputasi, CVE, dan temuan aset terkait.

**Status S3 (2026-11-27): selesai.** 15 sumber threat intel (sumber tanpa key tetap jalan dengan sumber gratis),
CVE via CVEDB + EPSS + KEV, typosquat engine sendiri (tanpa dependensi dnstwist), bucket finder S3/GCS/Azure,
GitHub secret scan dengan masking, dashboard `/providers`. Recon pipeline diperkaya otomatis; test di `tests/test_s3.py`.

---

## S4 — People, Image & Geo (12.5 PD)

| # | Task | Effort |
|---|---|---|
| 4.1 | Phone upgrade: footprinting, prefix operator ID, cek WA/Telegram | 2.5 |
| 4.2 | Image: EXIF/GPS, OCR (Tesseract), reverse image search | 2.5 |
| 4.3 | Corporate/local: AHU/OSS, GLEIF LEI, OpenCorporates, Scholar/ORCID | 2.5 |
| 4.4 | Geo: reverse geocode, Overpass/OSM, Sentinel/FIRMS, suncalc | 2 |
| 4.5 | Social API: GitHub, Reddit, Mastodon, Bluesky, Telegram, TikTok | 3 |

**DoD S4:** modul people/image/geo terintegrasi ke unified search.

**Status S4 (2026-11-27): selesai.** Catatan desain: cek WA/Telegram dibuat sebagai tautan manual
(bukan enumerasi otomatis — melanggar ToS & rawan penyalahgunaan). AHU/OSS tidak punya API publik →
tautan registri; Scholar diganti OpenAlex (API resmi). Reddit butuh app OAuth; TikTok best-effort (scraping).
Test di `tests/test_s4.py`.

---

## S5 — Case Management & Reporting (19.5 PD)

| # | Task | Effort |
|---|---|---|
| 5.1 | Model case/workspace (case → entities → findings) | 2 |
| 5.2 | Entity graph (vis-network) + timeline | 3 |
| 5.3 | Notes, tags, attachments, chain of custody | 2 |
| 5.4 | Report generator PDF/Markdown/JSON/CSV | 3 |
| 5.5 | Watchlist + alert (email/webhook) | 2.5 |
| 5.6 | One-click recon pipeline (domain → DNS → subdomain → ...) | 3 |
| 5.7 | REST API + API token | 2.5 |
| 5.8 | CLI + browser extension | 2 |

**DoD S5:** satu case bisa dibuat, diisi otomatis, dan diekspor laporan.

---

## S6 — Polish & Scale (9 PD, opsional)

| # | Task | Effort |
|---|---|---|
| 6.1 | i18n ID/EN | 2 |
| 6.2 | Command palette + UI/UX polish | 2 |
| 6.3 | Performance tuning: DB index, cache warmup, conn pool | 2 |
| 6.4 | Logging & monitoring (Sentry/Prometheus) | 1.5 |
| 6.5 | Dokumentasi + onboarding | 1.5 |

---

## Matriks Prioritas (impact vs effort)

| Item | Impact | Effort | Rekomendasi |
|---|---|---|---|
| Fix 3 tool rusak | Tinggi | Rendah | **Sekarang** |
| Username (WhatsMyName) | Tinggi | Sedang | Sprint pertama |
| Email intelligence | Tinggi | Sedang | Sprint pertama |
| DNS/DMARC/DNSSEC | Tinggi | Rendah | Quick win |
| Async job queue | Tinggi | Sedang | Wajib sebelum scan |
| Subdomain multi-source | Tinggi | Sedang | Fase inti |
| Case + report | Sangat tinggi | Tinggi | Diferensiasi utama |
| Shodan/VT | Sedang | Sedang | Butuh budget API |
| i18n | Rendah | Sedang | Terakhir |

---

## Quick wins (≤ 3 PD, bisa hari ini)

1. Fix `tech_tool` (0.5 PD)
2. Fix DNS SPF/DMARC (0.5 PD)
3. `ip_tool` HTTPS + timeout (0.25 PD)
4. `.gitignore` + untrack cache (0.5 PD)
5. Relabel "Search Person" (0.25 PD)
6. Security headers grader (1 PD)

---

## Risiko teknis

- **API berbayar/kuota**: Shodan, HIBP, Censys, VT — siapkan fallback gratis & cache agresif.
- **Rate limit** sumber publik (crt.sh, OTX) — wajib backoff + cache.
- **Playwright/nmap** butuh resource & privilege — jalankan di worker terpisah/container.
- **Skala data**: SQLite cukup sampai ~ratusan ribu baris; siapkan opsi Postgres.
- **Maintenance dataset** (WhatsMyName, Sherlock) — jadwalkan update otomatis.

---

## Struktur folder usulkan

```
motoku/
├── app.py               Flask routes dan config
├── config.py            Environment-based config
├── db.py                SQLite persistence + migrate legacy JSON
├── rate_limit.py        In-memory sliding-window limiter
├── extensions.py        db, cache, csrf, limiter, login
├── routes/              Blueprint per domain
├── services/
│   ├── providers/       shodan.py, vt.py, hibp.py, ...
│   ├── jobs/            tasks, queue
│   └── recon            pipeline orchestrator
├── templates/
├── static/
├── data/                SQLite + dataset CCTV
├── tests/
├── docker/
└── .env.example
```

---

## Rekomendasi urutan eksekusi

**S0 → S1 → S2 → S3/S4 (paralel) → S5 → S6.** Jika waktu terbatas, hentikan di akhir **S2** — sudah menjadi toolkit recon jauh lebih lengkap dan stabil.

---

## Catatan

- File roadmap ini akan disimpan di `ROADMAP.md` di root repo.
- Setiap fase bisa dipause dan dilanjutkan kapan saja.
- Estimasi effort bersifat estimatif; bisa berubah tergantung komplikasi integrasi API.
- Prioritas tetap pada stabilitas (S0) sebelum menambah fitur baru.