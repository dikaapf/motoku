# Panduan Developer

## Setup & test

```bash
cd motoku
python -m venv venv && source venv/bin/activate
pip install -r requirements-dev.txt
pytest            # semua test memalsukan jaringan
ruff check .
python scripts/i18n_check.py   # string yang belum diterjemahkan
```

CI (`.github/workflows/ci.yml`) menjalankan ruff + pytest di setiap push/PR.
Test memakai backend job `inline` (lihat `tests/conftest.py`), DB sementara,
dan cache memori baru per test.

## Menambah tool

1. Buat `tools/nama_tool.py` yang mengembalikan dict JSON-serializable dan
   melempar `ValueError` untuk input salah.
2. Panggil sumber eksternal lewat provider (lihat di bawah).
3. Tambah route di `app.py` (atau Blueprint di `routes/`) dan template yang
   memakai macro `_macros.html`: `result_data`, `result_card`, `export_toolbar`
   (otomatis memberi tombol Salin/JSON/CSV/Case).
4. Daftarkan di `services/catalog.py` → muncul di menu, beranda, dan palette.
5. (Opsional) tipe input baru di `services/detect.py`.
6. (Opsional) extractor di `services/importer.py` (`EXTRACTORS[endpoint]`)
   agar tombol Case menghasilkan entity yang tepat.
7. (Opsional) tool sinkron untuk API di `routes/api.py::_tools()`.
8. Tulis test dengan jaringan dipalsukan (`monkeypatch` pada `requests`).

## Menambah provider

```python
# services/providers/registry.py
NEWSRC = register('newsrc', category='Reputasi', ttl=12 * 3600, daily_quota=500,
                  key_env='MOTOKU_NEWSRC_API_KEY', key_optional=False,
                  description='…', homepage='https://…')

# tools/…
data = NEWSRC.fetch(cache_key, lambda: requests.get(url, headers=…, timeout=15).json())
```

`fetch` menangani cache, kuota, error accounting, dan `ProviderUnavailable`
bila key tidak ada. Untuk kuota dari header API panggil
`NEWSRC.set_remote_quota(remaining, limit)`. Untuk sumber yang sering gagal
sementara pakai `services.http.get_with_retry`.

## Menambah job

```python
# services/job_handlers.py
@jobs.handler('newscan', 'Label untuk UI')
def newscan_job(ctx, target):
    ctx.progress(10, 'Mulai')
    return tool.run(target, progress=lambda p, m: ctx.progress(p, m))
```

Route: `job_id = jobs.enqueue('newscan', target, {'target': target})` lalu
redirect ke `?job=<id>`; template memakai macro `job_progress(job)`.

## i18n

Teks sumber berbahasa Indonesia dibungkus `{{ _('Teks') }}` (template) atau
`gettext('Teks')` (Python). Parameter: `_('Ada {n} item', n=3)`. Jalankan
`python scripts/i18n_check.py --write` untuk menambah kunci baru ke
`translations/en.json`, lalu terjemahkan nilainya. Test gagal bila ada string
tanpa terjemahan.

## Konvensi

- Pesan untuk pengguna dalam Bahasa Indonesia (diterjemahkan lewat i18n).
- Jangan menyimpan atau menampilkan rahasia mentah; gunakan `cloud_tool.mask`.
- Scan aktif harus eksplisit dipicu pengguna dan diberi peringatan izin.
- Perubahan pada case selalu lewat `services/casedb` agar tercatat di custody.
