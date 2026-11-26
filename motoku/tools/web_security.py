"""HTTP security headers grader and TLS certificate inspector."""

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import urllib3

from services.providers.registry import HTTP_HEADERS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = 'Mozilla/5.0 (compatible; Motoku-OSINT/1.1; +security-headers)'

# (header, weight, recommendation)
HEADER_RULES = [
    ('strict-transport-security', 20,
     'Strict-Transport-Security: max-age=31536000; includeSubDomains'),
    ('content-security-policy', 25,
     "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'self'"),
    ('x-frame-options', 10, 'X-Frame-Options: DENY (atau CSP frame-ancestors)'),
    ('x-content-type-options', 10, 'X-Content-Type-Options: nosniff'),
    ('referrer-policy', 10, 'Referrer-Policy: strict-origin-when-cross-origin'),
    ('permissions-policy', 10, 'Permissions-Policy: geolocation=(), camera=(), microphone=()'),
    ('cross-origin-opener-policy', 5, 'Cross-Origin-Opener-Policy: same-origin'),
    ('cross-origin-resource-policy', 5, 'Cross-Origin-Resource-Policy: same-origin'),
]
LEAKY_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
                 'x-generator', 'via']


def normalise_url(url):
    url = (url or '').strip()
    if not url:
        raise ValueError('URL kosong')
    if not url.lower().startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError('URL tidak valid')
    return url


def _evaluate_header(name, value):
    """Return (status, note) for a present header value."""
    v = value.lower()
    if name == 'strict-transport-security':
        try:
            max_age = int(v.split('max-age=')[1].split(';')[0].strip().strip('"'))
        except (IndexError, ValueError):
            return 'warn', 'max-age tidak terbaca'
        if max_age < 15552000:
            return 'warn', f'max-age={max_age} < 180 hari'
        return 'pass', 'includeSubDomains' if 'includesubdomains' in v else 'OK'
    if name == 'content-security-policy':
        notes = []
        if "'unsafe-inline'" in v and 'nonce-' not in v and "'strict-dynamic'" not in v:
            notes.append("'unsafe-inline'")
        if "'unsafe-eval'" in v:
            notes.append("'unsafe-eval'")
        if 'default-src' not in v and 'script-src' not in v:
            notes.append('tanpa default-src/script-src')
        return ('warn', 'Lemah: ' + ', '.join(notes)) if notes else ('pass', 'OK')
    if name == 'x-content-type-options':
        return ('pass', 'OK') if v.strip() == 'nosniff' else ('warn', 'Harus "nosniff"')
    if name == 'x-frame-options':
        return ('pass', 'OK') if v.strip() in ('deny', 'sameorigin') else ('warn', 'Nilai tidak umum')
    if name == 'referrer-policy':
        if v.strip() in ('unsafe-url', 'no-referrer-when-downgrade'):
            return 'warn', 'Membocorkan URL lengkap'
        return 'pass', 'OK'
    return 'pass', 'OK'


def grade(score):
    for threshold, letter in ((95, 'A+'), (80, 'A'), (65, 'B'), (50, 'C'), (35, 'D'), (20, 'E')):
        if score >= threshold:
            return letter
    return 'F'


def analyse_headers(url):
    url = normalise_url(url)

    def run():
        cert_error = None
        try:
            resp = requests.get(url, headers={'User-Agent': USER_AGENT}, timeout=10,
                                allow_redirects=True)
        except requests.exceptions.SSLError as e:
            # Still grade the headers of sites with a broken certificate; the
            # TLS section reports the certificate problem itself.
            cert_error = str(e.args[0] if e.args else e)[:200]
            resp = requests.get(url, headers={'User-Agent': USER_AGENT}, timeout=10,
                                allow_redirects=True, verify=False)
        return {
            'cert_error': cert_error,
            'final_url': resp.url,
            'status_code': resp.status_code,
            'headers': dict(resp.headers),
            'set_cookie': resp.raw.headers.getlist('Set-Cookie')
            if hasattr(resp.raw.headers, 'getlist') else [],
            'redirects': [r.url for r in resp.history],
        }

    try:
        fetched = HTTP_HEADERS.fetch(url, run)
    except requests.RequestException as e:
        raise ValueError(f'Gagal mengambil {url}: {type(e).__name__}')

    headers = {k.lower(): v for k, v in fetched['headers'].items()}
    https = fetched['final_url'].lower().startswith('https://')
    checks = []
    score = 0
    total = sum(w for _, w, _ in HEADER_RULES)
    csp = headers.get('content-security-policy', '').lower()

    for name, weight, recommendation in HEADER_RULES:
        value = headers.get(name)
        if name == 'x-frame-options' and value is None and 'frame-ancestors' in csp:
            checks.append({'header': name, 'status': 'pass', 'value': '(via CSP frame-ancestors)',
                           'note': 'OK', 'recommendation': None})
            score += weight
            continue
        if name == 'strict-transport-security' and not https:
            checks.append({'header': name, 'status': 'fail', 'value': None,
                           'note': 'Situs tidak memakai HTTPS', 'recommendation':
                           'Aktifkan HTTPS dan redirect HTTP → HTTPS, lalu tambahkan HSTS.'})
            continue
        if value is None:
            checks.append({'header': name, 'status': 'fail', 'value': None,
                           'note': 'Tidak ada', 'recommendation': recommendation})
            continue
        status, note = _evaluate_header(name, value)
        score += weight if status == 'pass' else weight // 2
        checks.append({'header': name, 'status': status, 'value': value, 'note': note,
                       'recommendation': None if status == 'pass' else recommendation})

    leaks = [{'header': h, 'value': headers[h]} for h in LEAKY_HEADERS if h in headers]

    cookies = []
    for raw in fetched.get('set_cookie') or []:
        lower = raw.lower()
        cookies.append({
            'name': raw.split('=', 1)[0].strip(),
            'secure': 'secure' in lower,
            'httponly': 'httponly' in lower,
            'samesite': ('samesite=' in lower and lower.split('samesite=')[1].split(';')[0]) or None,
        })

    pct = round(score * 100 / total)
    # Each leaking header costs a little; insecure cookies too.
    pct -= 2 * len(leaks)
    pct -= 3 * sum(1 for c in cookies if not (c['secure'] and c['httponly']))
    pct = max(0, min(100, pct))

    return {
        'url': url,
        'final_url': fetched['final_url'],
        'status_code': fetched['status_code'],
        'redirects': fetched.get('redirects', []),
        'cert_error': fetched.get('cert_error'),
        'https': https,
        'score': pct,
        'grade': grade(pct),
        'checks': checks,
        'leaks': leaks,
        'cookies': cookies,
        'raw_headers': fetched['headers'],
    }


def _name_to_str(name_tuple):
    parts = {}
    for rdn in name_tuple or ():
        for key, value in rdn:
            parts[key] = value
    return parts


def tls_info(host, port=443, timeout=8):
    context = ssl.create_default_context()
    verified = True
    verify_error = None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version()
                cipher = tls.cipher()
    except ssl.SSLCertVerificationError as e:
        verified = False
        verify_error = e.verify_message or str(e)
        insecure = ssl.create_default_context()
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with insecure.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                version = tls.version()
                cipher = tls.cipher()
        cert = _decode_der(der)
    except (OSError, ssl.SSLError) as e:
        raise ValueError(f'Tidak dapat membuka koneksi TLS ke {host}:{port} ({type(e).__name__})')

    not_before = _parse_cert_time(cert.get('notBefore'))
    not_after = _parse_cert_time(cert.get('notAfter'))
    days_left = (not_after - datetime.now(timezone.utc)).days if not_after else None
    sans = [v for k, v in cert.get('subjectAltName', ()) if k == 'DNS']

    issues = []
    if not verified:
        issues.append(f'Sertifikat tidak valid: {verify_error}')
    if days_left is not None and days_left < 0:
        issues.append('Sertifikat sudah kedaluwarsa')
    elif days_left is not None and days_left < 14:
        issues.append(f'Sertifikat akan kedaluwarsa dalam {days_left} hari')
    if version in ('TLSv1', 'TLSv1.1', 'SSLv3'):
        issues.append(f'Protokol usang: {version}')

    return {
        'host': host,
        'port': port,
        'verified': verified,
        'subject': _name_to_str(cert.get('subject')),
        'issuer': _name_to_str(cert.get('issuer')),
        'serial': cert.get('serialNumber'),
        'not_before': not_before.isoformat() if not_before else None,
        'not_after': not_after.isoformat() if not_after else None,
        'days_left': days_left,
        'sans': sans,
        'protocol': version,
        'cipher': cipher[0] if cipher else None,
        'cipher_bits': cipher[2] if cipher else None,
        'issues': issues,
    }


def _parse_cert_time(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _decode_der(der):
    """Best-effort decode of an unverified certificate via the cryptography lib."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID  # noqa: F401
    except ImportError:
        return {}
    cert = x509.load_der_x509_certificate(der)

    def name(n):
        return tuple(((attr.oid._name, attr.value),) for attr in n)

    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_list = tuple(('DNS', v) for v in sans.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        san_list = ()
    fmt = '%b %d %H:%M:%S %Y GMT'
    return {
        'subject': name(cert.subject),
        'issuer': name(cert.issuer),
        'serialNumber': format(cert.serial_number, 'X'),
        'notBefore': cert.not_valid_before_utc.strftime(fmt),
        'notAfter': cert.not_valid_after_utc.strftime(fmt),
        'subjectAltName': san_list,
    }


def analyse(url, include_tls=True):
    report = analyse_headers(url)
    report['tls'] = None
    report['tls_error'] = None
    if include_tls:
        host = urlparse(report['final_url']).hostname or urlparse(report['url']).hostname
        try:
            report['tls'] = tls_info(host)
        except ValueError as e:
            report['tls_error'] = str(e)
    return report
