# Panduan Pengguna

## 1. Pencarian terpadu

Ketik apa pun di kotak pencarian (navbar atau beranda). Motoku mendeteksi tipe
input dan menyarankan modul:

| Input | Contoh | Modul utama |
|---|---|---|
| Email | `user@contoh.co.id` | Email Intelligence, DNS Security domainnya |
| Domain | `contoh.co.id` | RDAP/WHOIS, Recon, DNS Security, Subdomain, TLS, Typosquat, Cloud |
| URL | `https://contoh.co.id/login` | Threat Intel, Headers & TLS, Tech Stack |
| URL gambar | `https://…/foto.jpg` | Image Forensics |
| IP | `203.0.113.10` | Threat Intel, IP Tracker, Port Scan |
| Nomor | `0812-3456-7890` | Phone Intel |
| Username | `johndoe` | Profil Sosial, WhatsMyName, Sherlock |
| Nama | `Budi Santoso` | Search Person, Korporasi & Akademik |
| Koordinat | `-6.1754, 106.8272` | Geo Intel |
| Hash | MD5/SHA1/SHA256 | Threat Intel |
| CVE | `CVE-2021-44228` | CVE · EPSS · KEV |
| LEI | `254900…` | GLEIF |

Halaman tool menerima `?q=…&auto=1` untuk langsung dijalankan, sehingga tautan
dari case/laporan bisa dibuka ulang.

**Pintasan:** `Ctrl/Cmd+K` membuka *command palette* (lompat ke tool, case,
atau cari target), `/` memfokuskan kotak pencarian.

## 2. Recon domain satu klik

`Recon` menjalankan, di background: RDAP → DNS security → subdomain
multi-source (+ wildcard) → takeover → HTTP probe → screenshot → TLS + CT →
port scan → Wayback/urlscan/favicon → threat intel → CVE (EPSS/KEV) →
typosquatting → bucket cloud. Progres tampil langsung; halaman boleh ditutup.
Pilih **Case baru** atau case yang ada agar hasilnya tersimpan otomatis.

Hasilnya berupa *temuan prioritas* (critical → low). Verifikasi selalu sebelum
bertindak: misalnya bucket yang cocok namanya belum tentu milik target, dan
username yang sama belum tentu orang yang sama.

## 3. Case management

- **Buat case** di `/cases` (judul, ruang lingkup/dasar izin, tag).
- **Isi otomatis**: tombol **Case** di setiap hasil tool mengekstrak entity
  (domain, IP, akun, CVE, lokasi, …), relasi, dan temuan. Job yang sudah
  selesai bisa diimpor dari tab Ringkasan.
- **Graf** memperlihatkan hubungan antar entity (CVE prioritas rendah dilipat).
- **Temuan** punya status: `open` → `confirmed` / `false_positive` / `resolved`.
- **Catatan** dan **lampiran bukti** (disimpan berdasarkan SHA-256).
- **Chain of custody**: setiap perubahan tercatat dalam rantai hash; halaman
  *custody* memverifikasi integritasnya.
- **Laporan**: PDF, HTML (cetak), Markdown, JSON, CSV (zip). Setiap ekspor
  di-hash dan dicatat.

## 4. Watchlist & alert

Tambahkan target di `/watchlist` atau dari tab case. Pemeriksaan pertama membuat
*baseline*; perubahan berikutnya menjadi alert:

| Target | Pemeriksaan |
|---|---|
| Domain | DNS (A/MX/NS/TXT), sertifikat TLS, subdomain baru (CT), reputasi, typosquat baru |
| IP | Port & CVE (InternetDB), reputasi |
| Email | Breach baru (HIBP, butuh key) |
| Username | Perubahan profil sosial |

Alert dikirim ke webhook (Slack, Discord, atau JSON generik) dan/atau email, dan
ditambahkan sebagai temuan pada case terkait.

## 5. Tips kualitas data

- Tambahkan API key di `/providers` untuk hasil lebih lengkap; sumber gratis
  tetap jalan tanpa key.
- Hasil di-cache (lihat TTL per provider); kuota harian lokal mencegah melewati
  batas provider.
- Bahasa antarmuka: menu **ID/EN** di navbar.
