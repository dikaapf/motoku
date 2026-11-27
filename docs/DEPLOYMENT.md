# Deployment

## Docker Compose (disarankan)

```bash
cd motoku
cp .env.example .env          # isi MOTOKU_SECRET_KEY, MOTOKU_AUTH_USER/PASSWORD, API key
docker compose up -d --build
```

Layanan: `motoku` (gunicorn gthread, port 5000), `worker` (RQ, menjalankan
recon/scan/watch), `redis` (cache, kuota, antrian). Volume `./data` menyimpan
SQLite, lampiran case, screenshot, dan dataset. Image menyertakan nmap,
Chromium, exiftool, dan Tesseract (eng+ind).

## Manual

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
gunicorn --bind 0.0.0.0:5000 --worker-class gthread --threads 16 --workers 2 --timeout 120 app:app
# opsional, untuk MOTOKU_JOB_BACKEND=rq:
rq worker --url "$MOTOKU_REDIS_URL" motoku
```

Paket sistem opsional: `nmap`, `chromium`, `libimage-exiftool-perl`,
`tesseract-ocr tesseract-ocr-ind`. Status semuanya terlihat di `/welcome`.

## Konfigurasi penting

| Variabel | Fungsi |
|---|---|
| `MOTOKU_SECRET_KEY` | **Wajib diganti.** Kunci sesi & CSRF |
| `MOTOKU_AUTH_USER` / `MOTOKU_AUTH_PASSWORD` | Basic auth untuk UI (API memakai token) |
| `MOTOKU_HOST` / `MOTOKU_PORT` | Bind address |
| `MOTOKU_REDIS_URL` | Cache + kuota + antrian bersama |
| `MOTOKU_JOB_BACKEND` | `thread` (default) atau `rq` |
| `MOTOKU_SCHEDULER` | Thread penjadwal watchlist (lease DB → hanya satu proses aktif) |
| `MOTOKU_DEFAULT_LANG` | `id` atau `en` |
| `MOTOKU_LOG_FORMAT` / `MOTOKU_LOG_LEVEL` | `text`/`json`, `INFO`/`DEBUG` |
| `MOTOKU_METRICS_TOKEN` | Token untuk `/metrics` (tanpa Basic auth) |
| `MOTOKU_SENTRY_DSN` | Error tracking (butuh `pip install sentry-sdk`) |
| `MOTOKU_SMTP_*`, `MOTOKU_ALERT_*` | Pengiriman alert |

Daftar lengkap ada di `motoku/.env.example`.

## Keamanan

- Jalankan di belakang reverse proxy HTTPS (Caddy/Nginx/Traefik). Set header
  `X-Forwarded-*` dan pertimbangkan SSO di proxy.
- Jangan pernah mengekspos tanpa autentikasi — banner dan `/welcome` akan
  memperingatkan bila `SECRET_KEY` default, debug aktif, atau server publik tanpa auth.
- Token API disimpan sebagai hash; cabut di `/settings/tokens`.
- Scan aktif (port scan, HTTP probe, bucket) keluar dari IP server — gunakan
  hanya pada target berizin.

## Monitoring

- `GET /healthz` — liveness; `GET /readyz` — DB + cache (503 bila bermasalah).
- `GET /metrics` — format Prometheus: request & latensi per proses, plus gauge
  dari DB (job per status, case, alert, watchlist, pemanggilan provider, umur
  job berjalan tertua). Contoh scrape:

```yaml
scrape_configs:
  - job_name: motoku
    metrics_path: /metrics
    authorization: { type: Bearer, credentials: "<MOTOKU_METRICS_TOKEN>" }
    static_configs: [{ targets: ["motoku:5000"] }]
```

- Log terstruktur JSON (`MOTOKU_LOG_FORMAT=json`) berisi `request_id` (juga di
  header `X-Request-ID`), path, status, dan durasi.

## Backup

SQLite memakai WAL. Backup online yang aman:

```bash
sqlite3 data/motoku.db ".backup data/backup-$(date +%F).db"
tar czf attachments-$(date +%F).tgz data/attachments
```

Lampiran disimpan berdasarkan SHA-256 dan diverifikasi saat diakses; verifikasi
rantai custody di halaman case setelah restore.

## Performa

- Koneksi SQLite dipakai ulang per thread, PRAGMA WAL/`synchronous=NORMAL`,
  index untuk query panas.
- Respons teks/JSON > 1 KB dikompresi gzip; aset statis di-cache 1 hari.
- Warm-up cache saat start (dataset lokal + katalog CISA KEV).
- SQLite cukup untuk ratusan ribu baris; untuk skala lebih besar siapkan Postgres
  (lapisan data terpusat di `db.py` dan `services/casedb.py`).
