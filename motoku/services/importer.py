"""Turn tool results into case entities, relations and findings.

Each extractor receives the JSON result of one tool and returns a bundle::

    {'entities': [{'key', 'type', 'value', 'label'?, 'data'?}],
     'relations': [{'src', 'dst', 'kind'}],
     'findings': [{'severity', 'title', 'detail', 'entity'?}]}

Unknown tools fall back to a conservative regex extractor (emails, IPs, CVEs,
URLs, domains).
"""

import ipaddress
import json
import re

from services import casedb

EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.I)
URL_RE = re.compile(r'\bhttps?://[^\s"\'<>]+', re.I)
DOMAIN_RE = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b', re.I)
FILE_EXT = {'js', 'css', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'json', 'xml', 'html', 'htm', 'php', 'py', 'txt',
            'conf', 'log', 'zip', 'gz', 'pdf', 'ico', 'woff', 'woff2', 'ttf', 'map', 'min', 'exe', 'dll'}


class Bundle:
    def __init__(self):
        self.entities = {}
        self.relations = []
        self.findings = []

    def entity(self, etype, value, label=None, data=None, tags=None):
        if value in (None, ''):
            return None
        value = casedb.normalise_value(etype, value)
        key = f'{etype}:{value}'
        if key in self.entities:
            if data:
                self.entities[key].setdefault('data', {}).update(data)
        else:
            self.entities[key] = {'key': key, 'type': etype, 'value': value, 'label': label,
                                  'data': data or {}, 'tags': tags or []}
        return key

    def rel(self, src, dst, kind):
        if src and dst and src != dst:
            self.relations.append({'src': src, 'dst': dst, 'kind': kind})

    def finding(self, severity, title, detail='', entity=None):
        self.findings.append({'severity': severity, 'title': title, 'detail': detail or '', 'entity': entity})

    def as_dict(self):
        return {'entities': list(self.entities.values()), 'relations': self.relations, 'findings': self.findings}


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _domain_type(name, root=None):
    if root and name != root and name.endswith('.' + root):
        return 'subdomain'
    return 'domain'


# ── tool-specific extractors ──
def ex_subdomains(b, data, root_key=None):
    domain = data.get('domain')
    root = root_key or b.entity('domain', domain)
    for h in data.get('hosts', []):
        if not h.get('alive'):
            continue
        sk = b.entity('subdomain', h['name'], data={'sources': h.get('sources'), 'cname': h.get('cname')})
        b.rel(sk, root, 'subdomain_of')
        for ip in h.get('a', [])[:4]:
            b.rel(sk, b.entity('ip', ip), 'resolves_to')
        for c in h.get('cname', [])[:1]:
            b.rel(sk, b.entity('domain', c), 'cname')
    for mx in data.get('mx_records', []):
        b.rel(root, b.entity('domain', mx['host'], data={'role': 'mx'}), 'mx')
    for ns in data.get('ns_records', []):
        b.rel(root, b.entity('domain', ns, data={'role': 'ns'}), 'ns')
    for f in (data.get('takeover') or {}).get('findings', []):
        b.finding('critical' if f['status'] == 'vulnerable' else 'high',
                  f'Potensi subdomain takeover: {f["host"]}', f'{f["service"]} via {f["cname"]}',
                  b.entity('subdomain', f['host']))
    return root


def ex_portscan(b, data):
    host = data.get('host')
    ip = data.get('ip')
    ipk = b.entity('ip', ip) if ip else None
    if host and host != ip:
        hk = b.entity('subdomain' if host.count('.') > 1 else 'domain', host)
        b.rel(hk, ipk, 'resolves_to')
    for p in data.get('open', []):
        sk = b.entity('service', f'{ip}:{p["port"]}/{p.get("protocol", "tcp")}',
                      label=f'{p["port"]} {p.get("service") or ""} {p.get("product") or ""}'.strip(),
                      data={'product': p.get('product'), 'cpe': p.get('cpe'), 'risk': p.get('risk')})
        b.rel(ipk, sk, 'exposes')
        if p.get('risk') in ('critical', 'high', 'medium'):
            b.finding(p['risk'], f'Port {p["port"]}/{p.get("service")} terbuka di {ip}', p.get('risk_reason'), sk)
    return ipk


def ex_cves(b, cves, attach_to=None, limit=200):
    for c in cves[:limit]:
        ck = b.entity('cve', c['id'], data={k: c.get(k) for k in ('cvss', 'epss', 'kev', 'priority', 'summary')})
        if attach_to:
            b.rel(attach_to, ck, 'vulnerable_to')
        if c.get('kev'):
            b.finding('critical', f'{c["id"]} ada di CISA KEV', (c.get('summary') or '')[:300], ck)


def ex_intel(b, data):
    kind, value = data.get('kind'), data.get('indicator')
    etype = {'ip': 'ip', 'domain': 'domain', 'url': 'url', 'hash': 'hash'}.get(kind, 'other')
    ek = b.entity(etype, value, data={'verdict': data.get('summary', {}).get('verdict')})
    verdict = data.get('summary', {}).get('verdict')
    if verdict in ('malicious', 'suspicious'):
        flagged = [r['source'] for r in data.get('results', []) if r.get('verdict') == verdict]
        b.finding('high' if verdict == 'malicious' else 'medium', f'{value} ditandai {verdict}',
                  'Sumber: ' + ', '.join(flagged), ek)
    for r in data.get('results', []):
        if r.get('status') != 'ok':
            continue
        d = r.get('data') or {}
        if r['source'] == 'ripestat':
            for a in d.get('asns', []):
                b.rel(ek, b.entity('asn', f'AS{a["asn"]}', label=a.get('holder')), 'announced_by')
        if r['source'] == 'ipinfo' and d.get('org'):
            b.rel(ek, b.entity('organization', d['org']), 'operated_by')
        for host in d.get('hostnames', [])[:10] if r['source'] in ('internetdb', 'shodan') else []:
            b.rel(b.entity(_domain_type(host), host), ek, 'resolves_to')
    for c in data.get('cves', [])[:100]:
        b.rel(ek, b.entity('cve', c), 'vulnerable_to')
    return ek


def ex_recon(b, data):
    root = b.entity('domain', data['domain'])
    whois = data.get('whois') or {}
    if whois.get('registrar'):
        b.rel(root, b.entity('organization', whois['registrar'], data={'role': 'registrar'}), 'registered_with')
    if whois.get('ip') and _is_ip(whois['ip']):
        b.rel(root, b.entity('ip', whois['ip']), 'resolves_to')
    if data.get('subdomains'):
        ex_subdomains(b, dict(data['subdomains'], takeover=data.get('takeover')), root)
    for h in data.get('http') or []:
        if h.get('alive'):
            uk = b.entity('url', h['final_url'], label=h.get('title'),
                          data={'status': h.get('status'), 'server': h.get('server')})
            host = h['host']
            b.rel(b.entity(_domain_type(host, data['domain']), host), uk, 'serves')
    ipk = ex_portscan(b, data['ports']) if data.get('ports') else None
    tls = data.get('tls') or {}
    cert = tls.get('certificate') or {}
    if cert.get('serial'):
        ck = b.entity('certificate', cert['serial'], label=(cert.get('subject') or {}).get('commonName'),
                      data={'issuer': (cert.get('issuer') or {}).get('organizationName'),
                            'not_after': cert.get('not_after'), 'days_left': cert.get('days_left')})
        b.rel(root, ck, 'presents')
    for lk in (data.get('threat_intel') or {}).get('lookups', []):
        ex_intel(b, lk)
    if data.get('cve'):
        ex_cves(b, data['cve'].get('cves', []), ipk)
    for t in (data.get('typosquat') or {}).get('registered', []):
        if t['risk'] in ('high', 'medium'):
            tk = b.entity('domain', t['ascii'], label=t['domain'], data={'fuzzer': t['fuzzer'], 'risk': t['risk']},
                          tags=['typosquat'])
            b.rel(tk, root, 'lookalike_of')
    for bucket in (data.get('cloud') or {}).get('buckets', []):
        bk = b.entity('bucket', f'{bucket["provider"]}:{bucket["name"]}', data={'status': bucket['status']})
        b.rel(bk, root, 'possibly_owned_by')
    for f in (data.get('summary') or {}).get('findings', []):
        b.finding(f['severity'], f['title'], f.get('detail'), root)
    return root


def ex_email(b, data):
    ek = b.entity('email', data['email'], data={'risk': data.get('risk_level'), 'disposable': data.get('disposable')})
    dk = b.entity('domain', data['domain'])
    b.rel(ek, dk, 'at_domain')
    for mx in data.get('mx', []):
        b.rel(dk, b.entity('domain', mx['host'], data={'role': 'mx'}), 'mx')
    g = data.get('gravatar') or {}
    if g.get('profile_url'):
        b.rel(ek, b.entity('account', g['profile_url'], label=f'Gravatar {g.get("display_name") or ""}'.strip()),
              'has_account')
        for a in g.get('accounts', []):
            b.rel(ek, b.entity('account', a['url'], label=a.get('name')), 'has_account')
    for br in (data.get('hibp') or {}).get('breaches', []):
        b.finding('high', f'{data["email"]} bocor di {br["title"]}', f'{br["date"]}: ' + ', '.join(br.get('data_classes', [])), ek)
    for note in data.get('risk_notes', []):
        b.finding('low', f'Email {data["email"]}: {note}', '', ek)


def ex_dns_security(b, data):
    dk = b.entity('domain', data['domain'], data={'dns_grade': data.get('grade')})
    for section in data.get('sections', {}).values():
        for c in section.get('checks', []):
            if c['status'] == 'fail':
                b.finding('medium', f'{data["domain"]}: {c["title"]}', c.get('recommendation') or c.get('detail'), dk)


def ex_web_security(b, data):
    from urllib.parse import urlparse
    host = urlparse(data.get('final_url') or data.get('url')).hostname
    uk = b.entity('url', data.get('final_url') or data.get('url'), data={'headers_grade': data.get('grade')})
    if host:
        b.rel(b.entity(_domain_type(host), host), uk, 'serves')
    if data.get('grade') in ('D', 'E', 'F'):
        missing = [c['header'] for c in data.get('checks', []) if c['status'] == 'fail']
        b.finding('low', f'Security header lemah ({data["grade"]}) di {host}', 'Tidak ada: ' + ', '.join(missing), uk)
    for issue in (data.get('tls') or {}).get('issues', []):
        b.finding('medium', f'TLS {host}: {issue}', '', uk)


def ex_domain(b, data):
    dk = b.entity('domain', data['domain'], data={'created': data.get('creation_date'),
                                                  'expires': data.get('expiration_date')})
    if data.get('registrar'):
        b.rel(dk, b.entity('organization', data['registrar'], data={'role': 'registrar'}), 'registered_with')
    if data.get('ip') and _is_ip(data['ip']):
        b.rel(dk, b.entity('ip', data['ip']), 'resolves_to')
    for ns in data.get('name_servers', []):
        b.rel(dk, b.entity('domain', ns, data={'role': 'ns'}), 'ns')
    for e in data.get('emails', []) or []:
        if EMAIL_RE.fullmatch(e):
            b.rel(dk, b.entity('email', e), 'contact')


def ex_social(b, data):
    uk = b.entity('username', data['username'])
    for r in data.get('results', []):
        for p in r.get('profiles', []):
            ak = b.entity('account', p['url'], label=f'{p["platform"]}: {p.get("username")}',
                          data={'platform': p['platform'], 'name': p.get('name'), 'stats': p.get('stats')})
            b.rel(uk, ak, 'has_account')
            if p.get('name'):
                b.rel(ak, b.entity('person', p['name']), 'display_name')
            if p.get('email'):
                b.rel(ak, b.entity('email', p['email']), 'lists_email')
            if p.get('location'):
                b.rel(ak, b.entity('location', p['location']), 'claims_location')
            for org in (p.get('extra') or {}).get('organizations', []) or []:
                b.rel(ak, b.entity('organization', f'GitHub org: {org}'), 'member_of')


def ex_username(b, data):
    uk = b.entity('username', data['username'])
    for r in data.get('results', []):
        if r['status'] == 'found':
            b.rel(uk, b.entity('account', r['url'], label=r['name'], data={'category': r.get('category')}), 'has_account')


def ex_phone(b, data):
    b.entity('phone', data['e164'], data={'operator': data.get('operator'), 'type': data.get('type'),
                                          'region': data.get('region_code')})


def ex_geo(b, data):
    label = (data.get('address') or {}).get('display_name')
    b.entity('location', f'{data["lat"]}, {data["lng"]}', label=label[:120] if label else None,
             data={'lat': data['lat'], 'lng': data['lng']})


def ex_image(b, data):
    fk = b.entity('hash', data['hashes']['sha256'], label=data.get('filename'),
                  data={'md5': data['hashes']['md5'], 'dhash': data['hashes']['dhash'],
                        'camera': ' '.join(filter(None, [data['exif_key'].get('Make'), data['exif_key'].get('Model')]))})
    gps = data.get('gps')
    if gps:
        lk = b.entity('location', f'{gps["lat"]}, {gps["lng"]}',
                      label=((gps.get('address') or {}).get('display_name') or '')[:120] or None,
                      data={'lat': gps['lat'], 'lng': gps['lng']})
        b.rel(fk, lk, 'taken_at')
        b.finding('medium', f'Gambar {data.get("filename") or ""} memuat GPS', f'{gps["lat"]}, {gps["lng"]}', fk)


def ex_corporate(b, data):
    for c in (data.get('results', {}).get('gleif') or {}).get('items', []):
        ok = b.entity('organization', c['name'], data={'lei': c['lei'], 'jurisdiction': c['jurisdiction'],
                                                       'address': c.get('legal_address')})
        if c.get('legal_address'):
            b.rel(ok, b.entity('location', c['legal_address']), 'registered_at')
    for a in (data.get('results', {}).get('openalex') or {}).get('items', []):
        pk = b.entity('person', a['name'], data={'openalex': a['url'], 'orcid': a.get('orcid')})
        if a.get('institution'):
            b.rel(pk, b.entity('organization', a['institution']), 'affiliated_with')


def ex_typosquat(b, data):
    root = b.entity('domain', data['domain'])
    for t in data.get('registered', []):
        if t['risk'] != 'low':
            b.rel(b.entity('domain', t['ascii'], label=t['domain'], tags=['typosquat'],
                           data={'fuzzer': t['fuzzer'], 'risk': t['risk']}), root, 'lookalike_of')
    high = [t['domain'] for t in data.get('registered', []) if t['risk'] == 'high']
    if high:
        b.finding('medium', f'{len(high)} domain typosquat berisiko tinggi untuk {data["domain"]}', ', '.join(high[:10]), root)


def ex_cloud(b, data):
    kk = b.entity('organization', data['keyword'])
    for bucket in data.get('buckets', []):
        bk = b.entity('bucket', f'{bucket["provider"]}:{bucket["name"]}', data={'status': bucket['status']})
        b.rel(bk, kk, 'possibly_owned_by')
        if bucket['status'] == 'public':
            b.finding('high', f'Bucket publik: {bucket["provider"]} {bucket["name"]}',
                      'Contoh objek: ' + ', '.join(bucket.get('sample', [])[:5]), bk)
    for r in (data.get('github') or {}).get('results', []):
        if r.get('findings'):
            uk = b.entity('url', r['url'], label=f'{r["repo"]}/{r["path"]}')
            b.finding('high', f'Kemungkinan rahasia bocor di {r["repo"]}/{r["path"]}',
                      ', '.join(f['type'] for f in r['findings']), uk)


def ex_cve_page(b, data):
    if data.get('mode') == 'cve':
        ex_cves(b, [data['cve']])
    else:
        ex_cves(b, data.get('cves', []))


def ex_generic(b, data):
    text = json.dumps(data, default=str)
    for m in set(EMAIL_RE.findall(text)):
        b.entity('email', m)
    for m in set(CVE_RE.findall(text)):
        b.entity('cve', m)
    for m in set(IPV4_RE.findall(text)):
        if _is_ip(m) and not ipaddress.ip_address(m).is_private:
            b.entity('ip', m)
    urls = set(URL_RE.findall(text))
    for m in list(urls)[:100]:
        b.entity('url', m.rstrip('.,);\\'))
    emails = {e.split('@')[1].lower() for e in EMAIL_RE.findall(text)}
    for m in set(DOMAIN_RE.findall(text)):
        m = m.lower()
        if m.rsplit('.', 1)[-1] in FILE_EXT or _is_ip(m) or m in emails:
            continue
        b.entity('domain', m)


EXTRACTORS = {
    'recon': ex_recon, 'recon_report': ex_recon,
    'subdomain': lambda b, d: ex_subdomains(b, d), 'portscan': ex_portscan,
    'intel': ex_intel, 'email': ex_email, 'dns_security_page': ex_dns_security,
    'web_security_page': ex_web_security, 'domain': ex_domain, 'social': ex_social,
    'username': ex_username, 'phone': ex_phone, 'geo': ex_geo, 'image': ex_image,
    'corporate': ex_corporate, 'typosquat': ex_typosquat, 'typosquat_page': ex_typosquat,
    'cloud': ex_cloud, 'cve': ex_cve_page,
}


def extract(tool, data):
    b = Bundle()
    func = EXTRACTORS.get(tool)
    try:
        if func:
            func(b, data)
        else:
            ex_generic(b, data)
    except (KeyError, TypeError, AttributeError):
        # Shape mismatch (older result format) → still capture what we can.
        ex_generic(b, data)
    return b.as_dict()


def import_result(case_id, tool, data, actor=None, label=None):
    bundle = extract(tool, data)
    summary = None
    if label:
        summary = f'Import {tool}: {label}'
    return casedb.import_bundle(case_id, bundle, tool, actor, summary)


def import_job(case_id, job, actor=None):
    if job['status'] != 'finished' or job.get('result') is None:
        raise ValueError('Job belum selesai')
    return import_result(case_id, job['kind'], job['result'], actor, label=job.get('target'))
