"""Domain registration lookup: RDAP first, legacy WHOIS as fallback."""

import socket
from urllib.parse import urlparse

import requests

from services.providers.registry import RDAP, WHOIS

RDAP_BOOTSTRAP = 'https://rdap.org/domain/{domain}'
UNKNOWN = 'Tidak diketahui'


def clean_domain(value):
    value = (value or '').strip().lower()
    if not value:
        raise ValueError('Domain kosong')
    if '://' not in value:
        value = 'http://' + value
    parsed = urlparse(value)
    host = (parsed.hostname or '').rstrip('.')
    if host.startswith('www.'):
        host = host[4:]
    if not host or '.' not in host:
        raise ValueError('Domain tidak valid')
    return host


def _vcard_field(vcard, field):
    for item in (vcard or [None, []])[1]:
        if item and item[0] == field:
            value = item[3]
            if isinstance(value, list):
                value = ', '.join(str(v) for v in value if v)
            return value
    return None


def _entity(entities, role):
    for ent in entities or []:
        if role in (ent.get('roles') or []):
            return ent
        nested = _entity(ent.get('entities'), role)
        if nested:
            return nested
    return None


def parse_rdap(data):
    events = {e.get('eventAction'): e.get('eventDate') for e in data.get('events', [])}
    registrar = _entity(data.get('entities'), 'registrar') or {}
    registrant = _entity(data.get('entities'), 'registrant') or {}
    abuse = _entity(registrar.get('entities'), 'abuse') or {}

    registrar_name = _vcard_field(registrar.get('vcardArray'), 'fn')
    iana_id = next((p.get('identifier') for p in registrar.get('publicIds', [])
                    if p.get('type') == 'IANA Registrar ID'), None)

    return {
        'source': 'RDAP',
        'domain': (data.get('ldhName') or '').lower(),
        'handle': data.get('handle'),
        'registrar': registrar_name or UNKNOWN,
        'registrar_iana_id': iana_id,
        'registrar_url': next((link.get('href') for link in registrar.get('links', [])
                               if link.get('rel') in ('about', 'self')), None),
        'abuse_email': _vcard_field(abuse.get('vcardArray'), 'email'),
        'abuse_phone': _vcard_field(abuse.get('vcardArray'), 'tel'),
        'creation_date': events.get('registration') or UNKNOWN,
        'expiration_date': events.get('expiration') or UNKNOWN,
        'updated_date': events.get('last changed') or UNKNOWN,
        'name_servers': sorted((ns.get('ldhName') or '').lower()
                               for ns in data.get('nameservers', []) if ns.get('ldhName')),
        'status': data.get('status', []),
        'dnssec': (data.get('secureDNS') or {}).get('delegationSigned'),
        'org': _vcard_field(registrant.get('vcardArray'), 'org') or UNKNOWN,
        'country': _vcard_field(registrant.get('vcardArray'), 'adr') or UNKNOWN,
        'emails': [e for e in [_vcard_field(registrant.get('vcardArray'), 'email')] if e],
        'rdap_url': next((link.get('href') for link in data.get('links', [])
                          if link.get('rel') == 'self'), None),
    }


def rdap_lookup(domain):
    def run():
        resp = requests.get(RDAP_BOOTSTRAP.format(domain=domain),
                            headers={'Accept': 'application/rdap+json'},
                            timeout=10, allow_redirects=True)
        if resp.status_code == 404:
            raise LookupError('RDAP: domain tidak terdaftar atau TLD belum mendukung RDAP')
        resp.raise_for_status()
        return parse_rdap(resp.json())

    return RDAP.fetch(domain, run)


def whois_lookup(domain):
    def run():
        import whois

        w = whois.whois(domain)
        return {
            'source': 'WHOIS',
            'domain': domain,
            'registrar': w.get('registrar') or UNKNOWN,
            'creation_date': _fmt_date(w.get('creation_date')),
            'expiration_date': _fmt_date(w.get('expiration_date')),
            'updated_date': _fmt_date(w.get('updated_date')),
            'name_servers': sorted({str(n).lower() for n in (w.get('name_servers') or [])}),
            'status': _as_list(w.get('status')),
            'emails': _as_list(w.get('emails')),
            'org': w.get('org') or UNKNOWN,
            'country': w.get('country') or UNKNOWN,
        }

    return WHOIS.fetch(domain, run)


def lookup(domain):
    domain = clean_domain(domain)
    errors = []
    result = None
    try:
        result = rdap_lookup(domain)
    except Exception as e:
        errors.append(f'RDAP: {e}')
    if result is None:
        try:
            result = whois_lookup(domain)
        except Exception as e:
            errors.append(f'WHOIS: {e}')
    if result is None:
        raise ValueError('Gagal lookup domain — ' + '; '.join(errors))

    try:
        result['ip'] = socket.gethostbyname(domain)
    except OSError:
        result['ip'] = UNKNOWN
    result['fallback_reason'] = errors[0] if errors else None
    return result


def _as_list(value):
    if not value:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(dict.fromkeys(str(v) for v in value))
    return [str(value)]


def _fmt_date(d):
    if not d:
        return UNKNOWN
    if isinstance(d, list):
        d = d[0]
    return str(d)
