import whois
import socket


def lookup(domain):
    domain = domain.strip().lower()
    if not domain.startswith(('http://', 'https://')):
        domain = 'http://' + domain

    from urllib.parse import urlparse
    parsed = urlparse(domain)
    clean_domain = parsed.netloc or parsed.path

    ip = None
    try:
        ip = socket.gethostbyname(clean_domain)
    except socket.gaierror:
        pass

    try:
        w = whois.whois(clean_domain)
    except Exception as e:
        raise ValueError(f"Gagal query WHOIS: {e}")

    result = {
        'domain': clean_domain,
        'ip': ip or 'Tidak diketahui',
        'registrar': w.get('registrar') or 'Tidak diketahui',
        'creation_date': _fmt_date(w.get('creation_date')),
        'expiration_date': _fmt_date(w.get('expiration_date')),
        'updated_date': _fmt_date(w.get('updated_date')),
        'name_servers': w.get('name_servers') or [],
        'status': w.get('status') or [],
        'emails': w.get('emails') or [],
        'org': w.get('org') or 'Tidak diketahui',
        'country': w.get('country') or 'Tidak diketahui',
    }
    return result


def _fmt_date(d):
    if not d:
        return 'Tidak diketahui'
    if isinstance(d, list):
        d = d[0]
    return str(d)
