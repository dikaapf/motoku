# Dokumentasi Motoku OSINT

Motoku adalah toolkit OSINT berbasis web (Flask) untuk investigasi domain,
infrastruktur, orang, gambar, dan lokasi — lengkap dengan case management,
watchlist, REST API, CLI, dan ekstensi browser.

| Dokumen | Untuk siapa | Isi |
|---|---|---|
| [USER_GUIDE.md](USER_GUIDE.md) | Analis | Alur kerja, modul, case, laporan, watchlist, pintasan |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Admin / DevOps | Instalasi, Docker, konfigurasi, keamanan, monitoring, backup |
| [API.md](API.md) | Integrator | REST API v1, token, contoh, CLI, ekstensi |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Developer | Komponen, aliran data, job, provider, model case |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Kontributor | Menambah tool/provider/extractor, i18n, test, rilis |

Mulai cepat:

```bash
cd motoku
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env    # set MOTOKU_SECRET_KEY
python app.py           # http://127.0.0.1:5000 → buka /welcome
```

Status roadmap: lihat [`ROADMAP.md`](../ROADMAP.md).

> Gunakan hanya untuk tujuan yang sah: aset milik sendiri, penugasan berizin,
> riset, atau jurnalisme. Scan aktif hanya ke target yang Anda miliki atau
> berizin. Hormati privasi dan UU Pelindungan Data Pribadi.
