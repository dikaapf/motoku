# REST API v1, CLI, dan ekstensi

Dokumentasi interaktif tersedia di `/api/v1/docs` pada instance Anda.

## Autentikasi

Buat token di `/settings/tokens`. Kirim sebagai `Authorization: Bearer mtk_…`
(atau `X-API-Key`). Scope:

| Scope | Hak |
|---|---|
| `read` | Membaca case, job, watchlist, alert, laporan |
| `write` | Membuat/mengubah case, entity, temuan, catatan, watchlist |
| `scan` | Menjalankan tool sinkron dan job background |

API tidak memakai cookie/CSRF maupun Basic auth; aksi tercatat di chain of
custody sebagai `api:<nama token>`.

## Endpoint

| Method | Path | Scope | Keterangan |
|---|---|---|---|
| GET | `/api/v1/me` | read | Info token |
| GET | `/api/v1/detect?q=` | read | Deteksi tipe input |
| GET | `/api/v1/tools` | read | Daftar tool sinkron |
| POST | `/api/v1/tools/<name>` | scan | `{"value": "...", "case_id"?: "..."}` |
| POST | `/api/v1/jobs` | scan | `{"kind": "recon", "params": {...}, "case_id"?}` → 202 |
| GET | `/api/v1/jobs/<id>` | read | Status & hasil |
| GET/POST | `/api/v1/cases` | read/write | Daftar / buat case |
| GET | `/api/v1/cases/<id>` | read | Entity, temuan, relasi, custody |
| POST | `/api/v1/cases/<id>/entities` · `/findings` · `/notes` | write | Tambah data |
| POST | `/api/v1/cases/<id>/import` | write | `{"job_id"}` atau `{"tool", "data"}` |
| GET | `/api/v1/cases/<id>/report?format=json\|md` | read | Laporan |
| GET/POST | `/api/v1/watchlist` | read/write | Watch item |
| GET | `/api/v1/alerts` | read | Alert (`?case_id`, `?unacked=1`) |

Tool sinkron: `dns`, `dns-security`, `web-security`, `domain`, `email`,
`intel`, `cve`, `tls`, `phone`, `geo`, `social`, `corporate`.
Job: `recon`, `subdomain`, `portscan`, `username`, `typosquat`, `cloud`.
Progres job juga tersedia sebagai Server-Sent Events di `/api/jobs/<id>/events`.

## Contoh

```bash
export MOTOKU_URL=https://motoku.internal MOTOKU_TOKEN=mtk_...
H="Authorization: Bearer $MOTOKU_TOKEN"

CASE=$(curl -s -X POST -H "$H" -H 'Content-Type: application/json' \
  -d '{"title": "Phishing brand X"}' $MOTOKU_URL/api/v1/cases | jq -r .id)

curl -s -X POST -H "$H" -H 'Content-Type: application/json' \
  -d "{\"kind\": \"recon\", \"params\": {\"domain\": \"contoh.co.id\"}, \"case_id\": \"$CASE\"}" \
  $MOTOKU_URL/api/v1/jobs

curl -s -H "$H" "$MOTOKU_URL/api/v1/cases/$CASE/report?format=md" > laporan.md
```

## CLI

```bash
python cli.py detect contoh.co.id
python cli.py tool dns-security contoh.co.id
python cli.py recon contoh.co.id --case "$CASE" --wait
python cli.py case list | case show <id> | case report <id> --format md
python cli.py watch add domain contoh.co.id --case <id> --webhook https://hooks.slack.com/...
python cli.py alerts --unacked
python cli.py watch-run        # jalankan watchlist jatuh tempo secara lokal (cron)
```

Tambahkan `--json` untuk keluaran mesin.

## Ekstensi browser

Folder `motoku/extension/` (Manifest V3). Muat lewat `chrome://extensions` →
*Load unpacked*, lalu isi URL server dan token di *Options*. Fitur: klik kanan
teks/tautan/gambar/halaman → Motoku, pencarian dari popup, tambah halaman ke
case, cek reputasi situs aktif.
