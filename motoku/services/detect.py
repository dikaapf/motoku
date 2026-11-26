"""Detect what kind of OSINT target a free-text query is.

Used by the unified search bar to route a query to the right tools.
"""

import ipaddress
import re
from urllib.parse import urlparse

EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$')
DOMAIN_RE = re.compile(
    r'^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+'
    r'(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9\-]{2,59})$'
)
HASH_RE = re.compile(r'^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$')
CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.I)
COORD_RE = re.compile(r'^\s*-?\d{1,2}\.\d{2,}\s*,\s*-?\d{1,3}\.\d{2,}\s*$')
GMAPS_RE = re.compile(r'google\.[a-z.]+/maps/.*@-?\d+\.\d+,-?\d+\.\d+')
LEI_RE = re.compile(r'^[A-Z0-9]{18}[0-9]{2}$')
IMAGE_EXT_RE = re.compile(r'\.(jpe?g|png|gif|webp|tiff?|heic|bmp)$', re.I)
PHONE_RE = re.compile(r'^\+?[\d\s\-().]{7,20}$')
USERNAME_RE = re.compile(r'^@?[A-Za-z0-9._\-]{2,40}$')

# Each type maps to an ordered list of (endpoint, label, form field).
# The first entry is the primary tool.
ROUTES = {
    'email': [
        ('email', 'Email Intelligence', 'email'),
        ('dns_security_page', 'DNS Security (domain email)', 'domain'),
        ('username', 'Username (bagian lokal)', 'username'),
    ],
    'ip': [
        ('intel', 'Threat Intel (reputasi)', 'indicator'),
        ('ip_track', 'IP Tracker', 'ip'),
        ('portscan', 'Port Scan', 'target'),
    ],
    'hash': [
        ('intel', 'Threat Intel (hash file)', 'indicator'),
    ],
    'cve': [
        ('cve', 'CVE + EPSS + KEV', 'query'),
    ],
    'url': [
        ('intel', 'Threat Intel (URL)', 'indicator'),
        ('web_security_page', 'Security Headers & TLS', 'url'),
        ('tech', 'Tech Stack', 'url'),
        ('tls_page', 'TLS Scan & CT', 'host'),
        ('domain', 'Domain RDAP/WHOIS', 'domain'),
        ('dns_security_page', 'DNS Security', 'domain'),
    ],
    'domain': [
        ('domain', 'Domain RDAP/WHOIS', 'domain'),
        ('recon', 'Recon lengkap (background)', 'domain'),
        ('dns_security_page', 'DNS Security', 'domain'),
        ('dns', 'DNS Records', 'domain'),
        ('web_security_page', 'Security Headers & TLS', 'url'),
        ('subdomain', 'Subdomain', 'domain'),
        ('tls_page', 'TLS Scan & CT', 'host'),
        ('archive_page', 'Wayback & urlscan', 'domain'),
        ('intel', 'Threat Intel (reputasi)', 'indicator'),
        ('typosquat_page', 'Typosquatting', 'domain'),
        ('cloud', 'Cloud bucket & GitHub leak', 'keyword'),
        ('tech', 'Tech Stack', 'url'),
        ('dorks', 'Google Dorks', 'target'),
    ],
    'phone': [
        ('phone', 'Phone Intel & Footprint', 'number'),
    ],
    'username': [
        ('social', 'Profil Sosial (API)', 'username'),
        ('username', 'Username (WhatsMyName)', 'username'),
        ('username_deep', 'Deep Username (Sherlock)', 'username'),
    ],
    'name': [
        ('search_person', 'Search Person', 'name'),
        ('corporate', 'Korporasi & Akademik', 'query'),
        ('geo', 'Geo (sebagai nama tempat)', 'location'),
    ],
    'coords': [
        ('geo', 'Geo: alamat, POI, matahari', 'location'),
    ],
    'image_url': [
        ('image', 'Image Forensics (EXIF, OCR)', 'url'),
        ('intel', 'Threat Intel (URL)', 'indicator'),
    ],
    'lei': [
        ('corporate', 'GLEIF LEI', 'query'),
    ],
}

TYPE_LABELS = {
    'email': 'Email',
    'ip': 'Alamat IP',
    'hash': 'Hash file',
    'coords': 'Koordinat',
    'image_url': 'URL gambar',
    'lei': 'Kode LEI',
    'cve': 'CVE',
    'url': 'URL',
    'domain': 'Domain',
    'phone': 'Nomor telepon',
    'username': 'Username',
    'name': 'Nama orang',
}


def detect(query):
    """Return ``(type, normalised_value)`` for ``query`` or ``(None, query)``."""
    q = (query or '').strip()
    if not q:
        return None, q

    if EMAIL_RE.match(q):
        return 'email', q.lower()

    if CVE_RE.match(q):
        return 'cve', q.upper()

    if COORD_RE.match(q) or GMAPS_RE.search(q):
        return 'coords', q

    if LEI_RE.match(q):
        return 'lei', q.upper()

    if HASH_RE.match(q):
        return 'hash', q.lower()

    try:
        return 'ip', str(ipaddress.ip_address(q.strip('[]')))
    except ValueError:
        pass

    if re.match(r'^https?://', q, re.I):
        parsed = urlparse(q)
        if parsed.hostname:
            if IMAGE_EXT_RE.search(parsed.path):
                return 'image_url', q
            return 'url', q

    if DOMAIN_RE.match(q) and not q.replace('.', '').isdigit():
        return 'domain', q.lower().rstrip('.')

    digits = re.sub(r'\D', '', q)
    if PHONE_RE.match(q) and 7 <= len(digits) <= 15 and (q.startswith('+') or len(digits) >= 9):
        return 'phone', q

    if USERNAME_RE.match(q):
        return 'username', q.lstrip('@')

    if ' ' in q and len(q) <= 100:
        return 'name', q

    return None, q


def value_for_field(qtype, value, field):
    """Adapt the detected value to what a specific tool form expects."""
    if qtype == 'email':
        local, _, domain = value.partition('@')
        if field == 'domain':
            return domain
        if field == 'username':
            return local
    if qtype == 'url':
        host = urlparse(value).hostname or value
        if field in ('domain', 'target', 'host'):
            return host
    if qtype == 'domain' and field == 'url':
        return 'https://' + value
    return value


def routes_for(query):
    qtype, value = detect(query)
    tools = []
    for endpoint, label, field in ROUTES.get(qtype, []):
        tools.append({
            'endpoint': endpoint,
            'label': label,
            'field': field,
            'value': value_for_field(qtype, value, field),
        })
    return {
        'query': query,
        'type': qtype,
        'type_label': TYPE_LABELS.get(qtype, 'Tidak dikenali'),
        'value': value,
        'tools': tools,
    }
