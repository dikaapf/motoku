"""Central DNS resolver with DNS-over-HTTPS fallback.

Some networks (hotel Wi-Fi, VM NAT, corporate proxies) silently drop or empty
large UDP/TCP answers on port 53 — TXT records in particular. When the system
resolver gives no answer, we retry over DoH (Cloudflare JSON API by default) so
security checks such as SPF/DMARC are not reported as missing by mistake.
"""

import os
import re

import dns.resolver
import requests

LIFETIME = 5
DOH_URL = os.environ.get('MOTOKU_DOH_URL', 'https://cloudflare-dns.com/dns-query')

_NEGATIVE = (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout)


class NXDomain(Exception):
    pass


def doh_enabled():
    return os.environ.get('MOTOKU_DNS_DOH_FALLBACK', '1').strip().lower() in ('1', 'true', 'yes', 'on')


def _txt_from_wire(rdata):
    return b''.join(rdata.strings).decode(errors='replace')


def _txt_from_doh(data):
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    if not parts:
        return data
    return ''.join(p.replace('\\"', '"') for p in parts)


def doh_query(name, rtype, dnssec=False):
    """Return the raw DoH JSON answer for ``name``/``rtype``."""
    params = {'name': name, 'type': rtype}
    if dnssec:
        params['do'] = '1'
    resp = requests.get(DOH_URL, params=params,
                        headers={'Accept': 'application/dns-json'}, timeout=LIFETIME)
    resp.raise_for_status()
    return resp.json()


def _doh_records(name, rtype):
    data = doh_query(name, rtype)
    if data.get('Status') == 3:
        raise NXDomain(name)
    wanted = dns.rdatatype.from_text(rtype)
    out = []
    for ans in data.get('Answer') or []:
        if ans.get('type') != wanted:
            continue
        value = ans.get('data', '')
        out.append(_txt_from_doh(value) if rtype == 'TXT' else value.strip())
    return out


def resolve(name, rtype='A', *, raise_nx=False):
    """Resolve ``name`` and return a list of string records.

    TXT records are returned with their character-strings joined and without
    surrounding quotes. Returns ``[]`` when nothing is found. Raises
    :class:`NXDomain` only when ``raise_nx`` is true.
    """
    name = name.rstrip('.')
    try:
        answers = dns.resolver.resolve(name, rtype, lifetime=LIFETIME)
        if rtype == 'TXT':
            return [_txt_from_wire(r) for r in answers]
        return [str(r).strip() for r in answers]
    except dns.resolver.NXDOMAIN:
        if raise_nx:
            raise NXDomain(name)
        return []
    except _NEGATIVE:
        pass
    except Exception:
        pass

    if not doh_enabled():
        return []
    try:
        return _doh_records(name, rtype)
    except NXDomain:
        if raise_nx:
            raise
        return []
    except Exception:
        return []


def dnssec_validated(name):
    """Return True/False if a validating resolver sets the AD bit, else None."""
    try:
        return bool(doh_query(name, 'A', dnssec=True).get('AD'))
    except Exception:
        return None
