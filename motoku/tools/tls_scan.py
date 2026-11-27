"""TLS/SSL configuration scan and Certificate Transparency history."""

import socket
import ssl
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from services.http import get_with_retry
from services.providers.registry import CRTSH
from tools.web_security import tls_info

PROTOCOLS = [
    ('TLSv1.3', ssl.TLSVersion.TLSv1_3, 'good'),
    ('TLSv1.2', ssl.TLSVersion.TLSv1_2, 'good'),
    ('TLSv1.1', ssl.TLSVersion.TLSv1_1, 'deprecated'),
    ('TLSv1.0', ssl.TLSVersion.TLSv1, 'deprecated'),
]
WEAK_CIPHER_MARKERS = ('RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'MD5', 'anon')


def _try_protocol(host, port, version, timeout=6):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, OSError):
        return {'supported': None, 'note': 'Tidak bisa diuji oleh OpenSSL lokal'}
    if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        try:
            ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
        except ssl.SSLError:
            pass
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cipher = tls.cipher()
                return {'supported': True, 'cipher': cipher[0] if cipher else None,
                        'bits': cipher[2] if cipher else None}
    except ssl.SSLError as e:
        if 'UNSUPPORTED_PROTOCOL' in str(e).upper() and version in (ssl.TLSVersion.TLSv1,
                                                                    ssl.TLSVersion.TLSv1_1):
            # Some OpenSSL builds refuse to offer legacy versions at all.
            return {'supported': False, 'note': str(e.reason or '')}
        return {'supported': False}
    except OSError:
        return {'supported': False}


def scan_protocols(host, port=443):
    with ThreadPoolExecutor(max_workers=len(PROTOCOLS)) as pool:
        futures = {name: pool.submit(_try_protocol, host, port, ver) for name, ver, _ in PROTOCOLS}
    out = []
    for name, _, quality in PROTOCOLS:
        res = futures[name].result()
        res.update({'protocol': name, 'quality': quality})
        out.append(res)
    return out


def ct_history(domain, limit=50):
    """Certificates logged for ``domain`` (and its subdomains) via crt.sh."""
    def run():
        resp = get_with_retry('https://crt.sh/', params={'q': domain, 'output': 'json'},
                              headers={'User-Agent': 'Motoku-OSINT/1.2'}, timeout=30,
                              retry_statuses=(404, 429, 500, 502, 503, 504))
        resp.raise_for_status()
        rows = resp.json() if resp.text.strip() else []
        seen = {}
        for r in rows:
            cid = r.get('id')
            if cid in seen:
                continue
            seen[cid] = {
                'id': cid,
                'issuer': r.get('issuer_name', ''),
                'common_name': r.get('common_name', ''),
                'names': sorted(set((r.get('name_value') or '').split('\n'))),
                'not_before': r.get('not_before'),
                'not_after': r.get('not_after'),
            }
        return sorted(seen.values(), key=lambda c: c['not_before'] or '', reverse=True)

    certs = CRTSH.fetch(('ct', domain), run)
    issuers = Counter()
    for c in certs:
        org = [p.split('=', 1)[1] for p in c['issuer'].split(', ') if p.startswith('O=')]
        issuers[org[0] if org else c['issuer'][:60]] += 1
    return {
        'total': len(certs),
        'issuers': issuers.most_common(10),
        'recent': certs[:limit],
        'first_seen': certs[-1]['not_before'] if certs else None,
        'last_seen': certs[0]['not_before'] if certs else None,
    }


def grade(report):
    score = 100
    notes = []
    cert = report.get('certificate') or {}
    if cert and not cert.get('verified'):
        score -= 40
        notes.append('Sertifikat tidak dipercaya')
    if cert and cert.get('days_left') is not None and cert['days_left'] < 14:
        score -= 20
        notes.append('Sertifikat hampir/sudah kedaluwarsa')
    protos = {p['protocol']: p for p in report.get('protocols', [])}
    if protos.get('TLSv1.0', {}).get('supported'):
        score -= 20
        notes.append('TLS 1.0 masih aktif')
    if protos.get('TLSv1.1', {}).get('supported'):
        score -= 10
        notes.append('TLS 1.1 masih aktif')
    if not protos.get('TLSv1.3', {}).get('supported'):
        score -= 5
        notes.append('TLS 1.3 belum didukung')
    if not protos.get('TLSv1.2', {}).get('supported') and not protos.get('TLSv1.3', {}).get('supported'):
        score -= 30
        notes.append('Tidak mendukung TLS modern')
    for p in protos.values():
        if p.get('cipher') and any(m in p['cipher'] for m in WEAK_CIPHER_MARKERS):
            score -= 20
            notes.append(f'Cipher lemah: {p["cipher"]}')
            break
    if protos.get('TLSv1.0', {}).get('supported') or protos.get('TLSv1.1', {}).get('supported'):
        score = min(score, 84)  # legacy protocols cap the grade at B (like SSL Labs)
    score = max(0, score)
    letter = next((g for t, g in ((95, 'A+'), (85, 'A'), (70, 'B'), (55, 'C'), (40, 'D')) if score >= t), 'F')
    return score, letter, notes


def scan(host, port=443, include_ct=True):
    host = (host or '').strip().lower().split('://')[-1].split('/')[0]
    if ':' in host:
        host, _, p = host.partition(':')
        port = int(p) if p.isdigit() else port
    if not host:
        raise ValueError('Host kosong')
    report = {'host': host, 'port': port, 'certificate': None, 'certificate_error': None}
    try:
        report['certificate'] = tls_info(host, port)
    except ValueError as e:
        report['certificate_error'] = str(e)
    report['protocols'] = scan_protocols(host, port) if report['certificate'] else []
    if report['certificate']:
        report['score'], report['grade'], report['notes'] = grade(report)
    else:
        # No TLS service answering: nothing to grade.
        report['score'], report['grade'], report['notes'] = None, None, []
    report['ct'] = None
    report['ct_error'] = None
    if include_ct:
        base = host[4:] if host.startswith('www.') else host
        try:
            report['ct'] = ct_history(base)
        except Exception as e:
            report['ct_error'] = str(e)[:200]
    return report
