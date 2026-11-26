"""Email/DNS security posture analyser: SPF, DKIM, DMARC, DNSSEC, MTA-STS,
TLS-RPT, BIMI and CAA, with a scored grade and concrete recommendations."""

import re

import requests

from services import resolver
from services.providers.registry import MTA_STS
from tools.dns_tool import DKIM_SELECTORS

SPF_LOOKUP_MECHS = ('include', 'a', 'mx', 'ptr', 'exists', 'redirect')


def _txt(name):
    return resolver.resolve(name, 'TXT')


def _records(name, rtype):
    return resolver.resolve(name, rtype)


def _check(status, title, detail, weight=0, recommendation=None):
    return {'status': status, 'title': title, 'detail': detail,
            'weight': weight, 'recommendation': recommendation}


# ── SPF ──
def parse_spf(record):
    terms = record.split()[1:]
    mechanisms = []
    lookups = 0
    all_qualifier = None
    redirect = None
    for term in terms:
        qualifier = '+'
        if term[0] in '+-~?':
            qualifier, term = term[0], term[1:]
        name = re.split(r'[:=/]', term, maxsplit=1)[0].lower()
        value = term[len(name) + 1:] if len(term) > len(name) else ''
        if name in SPF_LOOKUP_MECHS:
            lookups += 1
        if name == 'all':
            all_qualifier = qualifier
        if name == 'redirect':
            redirect = value
        mechanisms.append({'qualifier': qualifier, 'name': name, 'value': value})
    return {'mechanisms': mechanisms, 'lookups': lookups,
            'all': all_qualifier, 'redirect': redirect}


def analyse_spf(domain):
    records = [r for r in _txt(domain) if r.lower().startswith('v=spf1')]
    result = {'records': records, 'parsed': None, 'checks': []}
    checks = result['checks']
    if not records:
        checks.append(_check('fail', 'SPF tidak ada',
                             'Tidak ada record TXT v=spf1.', 20,
                             'Publikasikan SPF, mis. "v=spf1 include:<provider> -all".'))
        return result
    if len(records) > 1:
        checks.append(_check('fail', 'Lebih dari satu SPF',
                             f'{len(records)} record SPF ditemukan (RFC 7208 mengharuskan satu).', 10,
                             'Gabungkan menjadi satu record SPF.'))
    parsed = parse_spf(records[0])
    result['parsed'] = parsed
    qualifier = parsed['all']
    if qualifier == '-':
        checks.append(_check('pass', 'SPF hard fail (-all)', 'Pengirim tidak sah ditolak.'))
    elif qualifier == '~':
        checks.append(_check('warn', 'SPF soft fail (~all)',
                             'Pengirim tidak sah hanya ditandai.', 5,
                             'Setelah semua pengirim terdaftar, ganti ke -all.'))
    elif qualifier in ('+', '?'):
        checks.append(_check('fail', f'SPF terlalu longgar ({qualifier}all)',
                             'Semua server boleh mengirim atas nama domain ini.', 15,
                             'Gunakan -all atau ~all.'))
    elif parsed['redirect']:
        checks.append(_check('info', 'SPF redirect', f'Kebijakan diambil dari {parsed["redirect"]}.'))
    else:
        checks.append(_check('warn', 'SPF tanpa mekanisme all',
                             'Default-nya neutral.', 5, 'Tambahkan -all di akhir record.'))
    if parsed['lookups'] > 10:
        checks.append(_check('fail', 'SPF melebihi 10 DNS lookup',
                             f'{parsed["lookups"]} lookup langsung (batas RFC 10) → permerror.', 10,
                             'Kurangi include atau gunakan SPF flattening.'))
    else:
        checks.append(_check('pass', 'Jumlah DNS lookup SPF',
                             f'{parsed["lookups"]} lookup langsung (batas 10, belum termasuk nested).'))
    return result


# ── DMARC ──
def parse_tags(record):
    tags = {}
    for part in record.split(';'):
        if '=' in part:
            k, v = part.split('=', 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def analyse_dmarc(domain):
    records = [r for r in _txt(f'_dmarc.{domain}') if r.lower().startswith('v=dmarc1')]
    result = {'records': records, 'tags': None, 'checks': []}
    checks = result['checks']
    if not records:
        checks.append(_check('fail', 'DMARC tidak ada',
                             'Tidak ada record di _dmarc.' + domain, 25,
                             'Mulai dengan "v=DMARC1; p=none; rua=mailto:dmarc@' + domain +
                             '", lalu naikkan ke quarantine/reject.'))
        return result
    tags = parse_tags(records[0])
    result['tags'] = tags
    policy = tags.get('p', '').lower()
    if policy == 'reject':
        checks.append(_check('pass', 'DMARC p=reject', 'Email palsu ditolak.'))
    elif policy == 'quarantine':
        checks.append(_check('warn', 'DMARC p=quarantine', 'Email palsu masuk spam.', 5,
                             'Naikkan ke p=reject bila laporan sudah bersih.'))
    else:
        checks.append(_check('fail', f'DMARC p={policy or "?"}',
                             'Mode monitor saja, tidak ada perlindungan spoofing.', 15,
                             'Naikkan ke p=quarantine lalu p=reject.'))
    pct = tags.get('pct', '100')
    if pct != '100':
        checks.append(_check('warn', f'DMARC pct={pct}', 'Kebijakan hanya berlaku sebagian.', 3,
                             'Set pct=100.'))
    if 'rua' not in tags:
        checks.append(_check('warn', 'DMARC tanpa rua', 'Tidak ada laporan agregat.', 3,
                             'Tambahkan rua=mailto:... untuk menerima laporan.'))
    else:
        checks.append(_check('pass', 'Laporan agregat (rua)', tags['rua']))
    sp = tags.get('sp')
    if sp and sp.lower() == 'none' and policy in ('reject', 'quarantine'):
        checks.append(_check('warn', 'Subdomain sp=none', 'Subdomain tidak terlindungi.', 3,
                             'Set sp=reject atau hapus tag sp.'))
    return result


# ── DKIM ──
def _rsa_bits_estimate(b64_key):
    """Estimate RSA modulus size from a base64 SubjectPublicKeyInfo blob."""
    if not b64_key:
        return 0
    der_len = len(b64_key.replace(' ', '')) * 3 // 4
    raw = max(0, der_len - 38) * 8  # ~38 bytes of ASN.1 framing + exponent
    for size in (512, 768, 1024, 1536, 2048, 3072, 4096):
        if raw <= size + 64:
            return size
    return raw


def analyse_dkim(domain, selectors=None):
    found = []
    for selector in selectors or DKIM_SELECTORS:
        for record in _txt(f'{selector}._domainkey.{domain}'):
            if 'p=' in record or 'v=dkim1' in record.lower():
                tags = parse_tags(record)
                key = tags.get('p', '')
                found.append({
                    'selector': selector,
                    'key_type': tags.get('k', 'rsa'),
                    'key_bits_approx': _rsa_bits_estimate(key),
                    'revoked': key == '',
                    'record': record[:300],
                })
    checks = []
    if found:
        checks.append(_check('pass', 'DKIM ditemukan',
                             'Selector: ' + ', '.join(f['selector'] for f in found)))
        weak = [f for f in found if f['key_type'] == 'rsa' and 0 < f['key_bits_approx'] < 1024]
        if weak:
            checks.append(_check('warn', 'Kunci DKIM lemah', 'Kunci RSA < 1024 bit.', 5,
                                 'Rotasi ke RSA 2048 bit.'))
    else:
        checks.append(_check('warn', 'DKIM tidak terdeteksi',
                             'Tidak ada selector umum yang ditemukan (selector bisa saja custom).', 5,
                             'Pastikan email ditandatangani DKIM.'))
    return {'selectors': found, 'checks': checks}


# ── DNSSEC ──
def analyse_dnssec(domain):
    ds = _records(domain, 'DS')
    dnskey = _records(domain, 'DNSKEY')
    validated = resolver.dnssec_validated(domain) if (ds or dnskey) else None
    checks = []
    if ds and dnskey:
        if validated is False:
            checks.append(_check('fail', 'DNSSEC rusak',
                                 'DS & DNSKEY ada tapi resolver tidak memvalidasi.', 10,
                                 'Periksa kecocokan DS di registrar dengan DNSKEY.'))
        else:
            checks.append(_check('pass', 'DNSSEC aktif', 'DS di parent dan DNSKEY ditemukan.'))
    elif dnskey and not ds:
        checks.append(_check('warn', 'DNSSEC belum lengkap',
                             'DNSKEY ada tapi DS belum dipasang di registrar.', 8,
                             'Tambahkan record DS di registrar.'))
    else:
        checks.append(_check('warn', 'DNSSEC tidak aktif',
                             'Zona tidak ditandatangani.', 8,
                             'Aktifkan DNSSEC di penyedia DNS dan registrar.'))
    return {'ds': ds, 'dnskey_count': len(dnskey), 'validated': validated, 'checks': checks}


# ── MTA-STS & TLS-RPT ──
def fetch_mta_sts_policy(domain):
    def run():
        resp = requests.get(f'https://mta-sts.{domain}/.well-known/mta-sts.txt', timeout=6)
        if resp.status_code != 200:
            return {'ok': False, 'error': f'HTTP {resp.status_code}'}
        policy = {}
        mx = []
        for line in resp.text.splitlines():
            if ':' in line:
                k, v = line.split(':', 1)
                k, v = k.strip().lower(), v.strip()
                if k == 'mx':
                    mx.append(v)
                else:
                    policy[k] = v
        policy['mx'] = mx
        return {'ok': True, 'policy': policy}

    try:
        return MTA_STS.fetch(domain, run)
    except Exception as e:
        return {'ok': False, 'error': type(e).__name__}


def analyse_mta_sts(domain):
    records = [r for r in _txt(f'_mta-sts.{domain}') if r.lower().startswith('v=stsv1')]
    tlsrpt = [r for r in _txt(f'_smtp._tls.{domain}') if r.lower().startswith('v=tlsrptv1')]
    result = {'records': records, 'policy': None, 'tlsrpt': tlsrpt, 'checks': []}
    checks = result['checks']
    if records:
        fetched = fetch_mta_sts_policy(domain)
        if fetched.get('ok'):
            policy = fetched['policy']
            result['policy'] = policy
            mode = policy.get('mode', '').lower()
            if mode == 'enforce':
                checks.append(_check('pass', 'MTA-STS enforce', 'TLS wajib untuk email masuk.'))
            else:
                checks.append(_check('warn', f'MTA-STS mode={mode or "?"}',
                                     'Policy belum di-enforce.', 3, 'Ubah mode ke enforce.'))
        else:
            checks.append(_check('fail', 'Policy MTA-STS tidak bisa diambil',
                                 fetched.get('error', ''), 5,
                                 f'Sajikan https://mta-sts.{domain}/.well-known/mta-sts.txt'))
    else:
        checks.append(_check('info', 'MTA-STS tidak ada',
                             'Email masuk bisa di-downgrade ke plaintext.', 3,
                             'Publikasikan _mta-sts TXT dan file policy.'))
    if tlsrpt:
        checks.append(_check('pass', 'TLS-RPT aktif', tlsrpt[0]))
    else:
        checks.append(_check('info', 'TLS-RPT tidak ada', 'Tidak ada laporan kegagalan TLS SMTP.', 1,
                             'Tambahkan _smtp._tls TXT "v=TLSRPTv1; rua=mailto:...".'))
    return result


def analyse_extra(domain):
    caa = _records(domain, 'CAA')
    bimi = [r for r in _txt(f'default._bimi.{domain}') if r.lower().startswith('v=bimi1')]
    checks = []
    if caa:
        checks.append(_check('pass', 'CAA ada', 'CA yang boleh menerbitkan sertifikat dibatasi.'))
    else:
        checks.append(_check('info', 'CAA tidak ada', 'Semua CA boleh menerbitkan sertifikat.', 2,
                             'Tambahkan CAA, mis. 0 issue "letsencrypt.org".'))
    if bimi:
        checks.append(_check('pass', 'BIMI ada', bimi[0][:200]))
    return {'caa': caa, 'bimi': bimi, 'checks': checks}


def grade(score):
    for threshold, letter in ((95, 'A+'), (85, 'A'), (70, 'B'), (55, 'C'), (40, 'D')):
        if score >= threshold:
            return letter
    return 'F'


def analyse(domain):
    domain = (domain or '').strip().lower().rstrip('.')
    domain = re.sub(r'^https?://', '', domain).split('/')[0]
    if not domain or '.' not in domain:
        raise ValueError('Domain tidak valid')
    try:
        resolver.resolve(domain, 'SOA', raise_nx=True)
    except resolver.NXDomain:
        raise ValueError(f'Domain {domain} tidak ditemukan')

    sections = {
        'spf': analyse_spf(domain),
        'dmarc': analyse_dmarc(domain),
        'dkim': analyse_dkim(domain),
        'dnssec': analyse_dnssec(domain),
        'mta_sts': analyse_mta_sts(domain),
        'extra': analyse_extra(domain),
    }
    penalty = sum(c['weight'] for s in sections.values() for c in s['checks']
                  if c['status'] in ('fail', 'warn', 'info'))
    score = max(0, 100 - penalty)
    recommendations = [c['recommendation'] for s in sections.values() for c in s['checks']
                       if c['recommendation'] and c['status'] != 'pass']
    return {
        'domain': domain,
        'score': score,
        'grade': grade(score),
        'sections': sections,
        'recommendations': recommendations,
    }
