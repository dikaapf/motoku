"""Single source of truth for the tool list: navbar menu, home page cards and
the command palette are all generated from here."""

# (endpoint, label, icon, color, description, keywords)
CATEGORIES = [
    ('workflow', 'Alur kerja', [
        ('recon', 'Recon Domain Lengkap', 'bi-radar', 'success',
         'Satu domain → subdomain, takeover, HTTP probe, TLS, port, CVE, typosquat, cloud — di background',
         'pipeline scan otomatis'),
        ('cases.index', 'Cases', 'bi-folder2-open', 'success',
         'Kelola investigasi: entity, graf, timeline, temuan, laporan PDF', 'case investigasi laporan report'),
        ('watch.index', 'Watchlist & Alert', 'bi-binoculars-fill', 'warning',
         'Pantau perubahan target dan kirim alert ke webhook/email', 'monitor pantau alert'),
        ('job_list', 'Background Jobs', 'bi-list-task', 'info', 'Status semua job yang berjalan', 'job antrian queue'),
    ]),
    ('people', 'Orang & identitas', [
        ('phone', 'Phone Intel', 'bi-telephone-fill', 'success',
         'Operator & prefix, format, footprint pencarian & messenger', 'nomor hp telepon whatsapp'),
        ('email', 'Email Intelligence', 'bi-envelope-fill', 'danger',
         'MX/SMTP, disposable, HIBP breach, Gravatar, reputasi', 'surel breach bocor'),
        ('username', 'Username Tracker', 'bi-person-badge-fill', 'warning',
         'Cek ~650 situs via dataset WhatsMyName, paralel', 'akun whatsmyname'),
        ('username_deep', 'Deep Username', 'bi-person-fill-gear', 'danger',
         'Sherlock 400+ platform + analisa Instagram', 'sherlock instagram'),
        ('social', 'Profil Sosial', 'bi-people-fill', 'warning',
         'Profil publik GitHub, Reddit, Mastodon, Bluesky, Telegram, TikTok', 'github mastodon bluesky tiktok telegram'),
        ('search_person', 'Search Person', 'bi-person-lines-fill', 'info',
         'Pencarian nama di banyak mesin pencari + Wikipedia', 'nama orang'),
        ('corporate', 'Korporasi & Akademik', 'bi-building-fill', 'primary',
         'GLEIF LEI, OpenCorporates, ORCID, OpenAlex, registri Indonesia', 'perusahaan pt lei peneliti'),
    ]),
    ('domain', 'Domain & web', [
        ('domain', 'Domain RDAP/WHOIS', 'bi-building', 'primary', 'Registrar, tanggal, name server, kontak abuse',
         'whois rdap registrar'),
        ('dns', 'DNS Lookup', 'bi-diagram-3', 'secondary', 'A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV', 'record'),
        ('dns_security_page', 'DNS Security', 'bi-shield-lock-fill', 'success',
         'Grade SPF, DKIM, DMARC, DNSSEC, MTA-STS, TLS-RPT, CAA', 'spf dmarc dkim dnssec email security'),
        ('web_security_page', 'Headers & TLS', 'bi-shield-check', 'info',
         'Grade security header HTTP + info sertifikat TLS', 'hsts csp header'),
        ('subdomain', 'Subdomain Enum', 'bi-diagram-3-fill', 'warning',
         'crt.sh, CertSpotter, OTX, HackerTarget, wildcard & takeover', 'subdomain takeover'),
        ('tls_page', 'TLS Scan & CT', 'bi-lock-fill', 'success',
         'Protokol TLS 1.0–1.3, sertifikat, Certificate Transparency', 'ssl sertifikat certificate'),
        ('tech', 'Tech Stack', 'bi-cpu', 'info', 'Deteksi teknologi website (Wappalyzer)', 'wappalyzer cms framework'),
        ('archive_page', 'Wayback & urlscan', 'bi-clock-history', 'warning',
         'URL historis, scan publik urlscan.io, favicon hash', 'wayback arsip archive favicon'),
        ('dorks', 'Google Dorks', 'bi-shield-shaded', 'success', 'Generator Google dork untuk domain', 'dork google'),
    ]),
    ('threat', 'Jaringan & ancaman', [
        ('intel', 'Threat Intel', 'bi-shield-exclamation', 'danger',
         'Reputasi IP/domain/URL/hash dari 15 sumber', 'reputasi virustotal abuseipdb shodan malware'),
        ('cve', 'CVE · EPSS · KEV', 'bi-bug-fill', 'warning',
         'CVE per produk/CPE dengan skor eksploitasi dan CISA KEV', 'vulnerability kerentanan'),
        ('ip_track', 'IP Tracker', 'bi-globe2', 'info', 'Geolokasi, ISP, ASN, deteksi IP sendiri', 'ip geolokasi'),
        ('portscan', 'Port Scanner', 'bi-plug-fill', 'danger', 'nmap -sV dengan rating risiko per port',
         'nmap port service'),
        ('typosquat_page', 'Typosquatting', 'bi-type', 'warning', 'Domain tiruan terdaftar + deteksi homograph IDN',
         'phishing brand homograph'),
        ('cloud', 'Cloud & GitHub Leak', 'bi-cloud-haze2-fill', 'info',
         'Bucket S3/GCS/Azure publik + kebocoran kredensial di GitHub', 's3 bucket github secret'),
    ]),
    ('media', 'Media & lokasi', [
        ('image', 'Image Forensics', 'bi-image-fill', 'info', 'EXIF/GPS, metadata, hash, OCR, reverse image search',
         'exif foto gambar ocr'),
        ('geo', 'Geo Intel', 'bi-globe-asia-australia', 'success',
         'Reverse geocode, POI, titik api FIRMS, posisi matahari & bayangan', 'peta lokasi koordinat matahari'),
        ('location_tracker', 'Location Tracker', 'bi-geo-alt-fill', 'danger',
         'Tautan pelacak lokasi berbasis persetujuan browser', 'lokasi tracking'),
        ('cctv', 'CCTV Finder', 'bi-camera-video-fill', 'info', 'CCTV publik Indonesia + scanner', 'kamera cctv'),
        ('flight_radar', 'Flight Radar', 'bi-airplane-engines', 'primary', 'Pesawat real-time (OpenSky)',
         'pesawat penerbangan adsb'),
    ]),
    ('admin', 'Sistem', [
        ('providers_dashboard', 'Provider & Kuota', 'bi-speedometer2', 'success',
         'Status API key, kuota, cache hit, riwayat 14 hari', 'api key kuota quota'),
        ('status', 'Status', 'bi-activity', 'success', 'Konfigurasi runtime, database, rate limit', 'health'),
        ('settings.tokens', 'API Token', 'bi-key-fill', 'warning', 'Token untuk REST API, CLI, ekstensi', 'token api'),
        ('api_v1.docs', 'Dokumentasi API', 'bi-braces', 'info', 'Endpoint REST API v1', 'rest api docs'),
        ('welcome', 'Onboarding', 'bi-rocket-takeoff', 'success', 'Checklist setup & panduan cepat', 'setup bantuan help'),
    ]),
]

HOME_HIDDEN = {'job_list', 'status', 'settings.tokens', 'api_v1.docs', 'welcome', 'providers_dashboard'}


def tools():
    out = []
    for cat_key, cat_label, items in CATEGORIES:
        for endpoint, label, icon, color, desc, keywords in items:
            out.append({'endpoint': endpoint, 'label': label, 'icon': icon, 'color': color, 'desc': desc,
                        'keywords': keywords, 'category': cat_key, 'category_label': cat_label})
    return out


def grouped():
    return [(key, label, [t for t in tools() if t['category'] == key]) for key, label, _ in CATEGORIES]


def count():
    return sum(1 for t in tools() if t['category'] not in ('admin', 'workflow'))
