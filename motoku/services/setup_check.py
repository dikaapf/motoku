"""First-run / health checklist shown on the onboarding page and as a banner."""

import os
import shutil

from flask import current_app, request

from services.i18n import gettext as _

DEFAULT_SECRETS = {'dev-only-change-me', 'change-me-in-production', ''}


def checks():
    cfg = current_app.config
    host_public = cfg.get('HOST') not in ('127.0.0.1', 'localhost', '::1')
    items = []

    def add(key, ok, title, detail, level='warning', link=None):
        items.append({'key': key, 'ok': ok, 'title': title, 'detail': detail, 'level': level, 'link': link})

    add('secret', cfg.get('SECRET_KEY') not in DEFAULT_SECRETS, _('SECRET_KEY sudah diganti'),
        _('Atur MOTOKU_SECRET_KEY ke nilai acak panjang, mis. hasil: python -c "import secrets;print(secrets.token_urlsafe(48))"'),
        'danger')
    auth_on = bool(cfg.get('AUTH_USER') and cfg.get('AUTH_PASSWORD'))
    add('auth', auth_on or not host_public, _('Akses dilindungi'),
        _('Server terbuka di jaringan tanpa Basic auth — set MOTOKU_AUTH_USER dan MOTOKU_AUTH_PASSWORD, atau jalankan di belakang reverse proxy dengan SSO.'),
        'danger')
    add('debug', not cfg.get('DEBUG'), _('Mode debug nonaktif'), _('Matikan MOTOKU_DEBUG di produksi.'), 'danger')
    add('csrf', cfg.get('CSRF_ENABLED', True), _('Proteksi CSRF aktif'), _('Set MOTOKU_CSRF_ENABLED=1.'), 'danger')
    add('redis', bool(os.environ.get('MOTOKU_REDIS_URL')), _('Redis untuk cache & job queue'),
        _('Opsional: MOTOKU_REDIS_URL membuat cache, kuota, dan job dibagi antar worker.'), 'info')

    from services import providers
    keyed = [p for p in providers.all_providers() if p.key_env and not p.key_optional]
    configured = sum(1 for p in keyed if p.has_key)
    add('providers', configured > 0, _('API key provider ({c}/{n} terpasang)', c=configured, n=len(keyed)),
        _('Sumber gratis sudah jalan; tambah key (VirusTotal, AbuseIPDB, Shodan, HIBP, …) untuk hasil lebih lengkap.'),
        'info', 'providers_dashboard')

    from tools import http_probe, image_tool, portscan_tool
    add('nmap', portscan_tool.nmap_available(), _('nmap terpasang'),
        _('Tanpa nmap, port scan memakai TCP connect tanpa deteksi versi (apt install nmap).'), 'info')
    add('chromium', bool(http_probe.screenshot_backend()), _('Chromium / Playwright tersedia'),
        _('Diperlukan untuk screenshot dan ekspor PDF (apt install chromium).'), 'info')
    add('tesseract', bool(image_tool.ocr_backend()), _('Tesseract OCR terpasang'),
        _('Diperlukan untuk OCR gambar (apt install tesseract-ocr tesseract-ocr-ind).'), 'info')
    add('exiftool', bool(shutil.which('exiftool')), _('exiftool terpasang'),
        _('Metadata gambar lengkap (apt install libimage-exiftool-perl).'), 'info')

    from services import api_tokens, casedb
    add('case', bool(casedb.list_cases(limit=1)), _('Case pertama dibuat'),
        _('Buat case lalu simpan hasil tool ke dalamnya dengan tombol Case.'), 'info', 'cases.index')
    add('token', bool(api_tokens.list_tokens()), _('API token dibuat'),
        _('Untuk CLI, ekstensi browser, dan integrasi lain.'), 'info', 'settings.tokens')
    return items


def banner_warnings():
    """Only critical problems; computed cheaply for every page."""
    if request.endpoint in (None, 'static') or request.path.startswith(('/api/', '/metrics', '/healthz')):
        return []
    cfg = current_app.config
    out = []
    if cfg.get('SECRET_KEY') in DEFAULT_SECRETS:
        out.append(_('SECRET_KEY masih default — sesi dapat dipalsukan.'))
    if cfg.get('HOST') not in ('127.0.0.1', 'localhost', '::1') and not (cfg.get('AUTH_USER') and cfg.get('AUTH_PASSWORD')):
        out.append(_('Server dapat diakses dari jaringan tanpa autentikasi.'))
    if cfg.get('DEBUG'):
        out.append(_('Mode debug aktif.'))
    return out
