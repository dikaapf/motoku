"""CVE mapping with CVSS, EPSS and CISA KEV.

* CPE → CVEs via Shodan CVEDB (free), with version fallbacks because scanners
  report versions like ``6.6.1p1`` that the CPE dictionary lacks.
* CVE details via CVEDB, falling back to NIST NVD 2.0.
* EPSS scores from FIRST (authoritative, batched) and the CISA KEV catalogue
  (downloaded once a day).
"""

import re
from concurrent.futures import ThreadPoolExecutor

from services.http import get_with_retry
from services.providers import registry as R

UA = {'User-Agent': 'Motoku-OSINT/1.3'}
CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.I)
KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'


def normalise_cve(value):
    value = (value or '').strip().upper()
    if not CVE_RE.match(value):
        raise ValueError('Format CVE tidak valid (contoh: CVE-2021-44228)')
    return value


def severity(cvss):
    if cvss is None:
        return 'unknown'
    if cvss >= 9:
        return 'critical'
    if cvss >= 7:
        return 'high'
    if cvss >= 4:
        return 'medium'
    if cvss > 0:
        return 'low'
    return 'none'


def priority(item):
    """Patch priority: KEV first, then EPSS, then CVSS."""
    if item.get('kev'):
        return 'P1'
    epss = item.get('epss') or 0
    cvss = item.get('cvss') or 0
    if epss >= 0.1 or (cvss >= 9 and epss >= 0.01):
        return 'P1' if epss >= 0.5 else 'P2'
    if cvss >= 7:
        return 'P3'
    return 'P4'


def sort_key(item):
    """Order: priority, then actively exploited (KEV), then EPSS, then CVSS."""
    return (item.get('priority', 'P9'), not item.get('kev'), -(item.get('epss') or 0), -(item.get('cvss') or 0))


# ── CPE handling ──
def cpe22_to_23(cpe):
    """``cpe:/a:vendor:product:1.2`` → ``cpe:2.3:a:vendor:product:1.2``."""
    cpe = (cpe or '').strip()
    if cpe.startswith('cpe:2.3:'):
        return cpe
    if cpe.startswith('cpe:/'):
        parts = cpe[5:].split(':')
        return 'cpe:2.3:' + ':'.join(parts)
    raise ValueError(f'CPE tidak dikenali: {cpe}')


def version_candidates(cpe23):
    """Yield the CPE and progressively looser versions (6.6.1p1 → 6.6.1 → 6.6)."""
    parts = cpe23.split(':')
    yield cpe23
    if len(parts) < 6 or parts[5] in ('', '*', '-'):
        return
    version = parts[5]
    seen = {version}
    numeric = re.match(r'\d+(?:\.\d+)*', version)
    candidates = []
    if numeric:
        nums = numeric.group(0).split('.')
        for n in range(len(nums), 1, -1):
            candidates.append('.'.join(nums[:n]))
    for v in candidates:
        if v not in seen:
            seen.add(v)
            yield ':'.join(parts[:5] + [v] + parts[6:])


def cves_for_cpe(cpe, limit=200):
    """Return ``{'cpe': matched_cpe, 'cves': [...]}`` (empty list if unknown)."""
    cpe23 = cpe22_to_23(cpe)
    for candidate in version_candidates(cpe23):
        def run(c=candidate):
            resp = get_with_retry('https://cvedb.shodan.io/cves', headers=UA, timeout=30,
                                  params={'cpe23': c, 'limit': limit, 'sort_by_epss': 'true'})
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return [_from_cvedb(x) for x in resp.json().get('cves', [])]
        cves = R.CVEDB.fetch(('cpe', candidate, limit), run)
        if cves is not None:
            return {'cpe': candidate, 'requested': cpe23, 'cves': cves}
    return {'cpe': None, 'requested': cpe23, 'cves': []}


def _from_cvedb(d):
    return {
        'id': d.get('cve_id'),
        'summary': (d.get('summary') or '')[:500],
        'cvss': d.get('cvss'),
        'cvss_version': d.get('cvss_version'),
        'epss': d.get('epss'),
        'epss_rank': d.get('ranking_epss'),
        'kev': bool(d.get('kev')),
        'ransomware': d.get('ransomware_campaign'),
        'published': (d.get('published_time') or '')[:10],
        'source': 'cvedb',
    }


# ── CVE details ──
def _nvd_detail(cve_id):
    def run():
        headers = dict(UA)
        if R.NVD.api_key:
            headers['apiKey'] = R.NVD.api_key
        resp = get_with_retry('https://services.nvd.nist.gov/rest/json/cves/2.0',
                              params={'cveId': cve_id}, headers=headers, timeout=30,
                              retry_statuses=(403, 429, 500, 502, 503))
        resp.raise_for_status()
        vulns = resp.json().get('vulnerabilities', [])
        if not vulns:
            return None
        c = vulns[0]['cve']
        desc = next((d['value'] for d in c.get('descriptions', []) if d.get('lang') == 'en'), '')
        metrics = c.get('metrics', {})
        cvss, version = None, None
        for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
            if metrics.get(key):
                cvss = metrics[key][0]['cvssData'].get('baseScore')
                version = metrics[key][0]['cvssData'].get('version')
                break
        return {'id': cve_id, 'summary': desc[:500], 'cvss': cvss, 'cvss_version': version,
                'epss': None, 'kev': bool(c.get('cisaExploitAdd')), 'published': c.get('published', '')[:10],
                'cwe': [d['value'] for w in c.get('weaknesses', []) for d in w.get('description', [])],
                'source': 'nvd'}
    return R.NVD.fetch(cve_id, run)


def cve_detail(cve_id):
    cve_id = normalise_cve(cve_id)

    def run():
        resp = get_with_retry(f'https://cvedb.shodan.io/cve/{cve_id}', headers=UA, timeout=30)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        d = resp.json()
        item = _from_cvedb(d)
        item['references'] = _as_list(d.get('references'))[:15]
        item['cpes'] = _as_list(d.get('cpes'))[:30]
        item['propose_action'] = d.get('propose_action')
        return item

    try:
        item = R.CVEDB.fetch(('cve', cve_id), run)
    except Exception:
        item = None
    if item is None:
        item = _nvd_detail(cve_id)
    if item is None:
        raise ValueError(f'{cve_id} tidak ditemukan')
    return item


def _as_list(value):
    if isinstance(value, list):
        return value
    if isinstance(value, str) and value.startswith('['):
        return re.findall(r"'([^']+)'", value)
    return []


# ── EPSS & KEV ──
def epss_scores(cve_ids):
    """Return ``{cve: {'epss': float, 'percentile': float}}`` (batched, 100 per call)."""
    ids = sorted({normalise_cve(c) for c in cve_ids})
    out = {}
    for i in range(0, len(ids), 100):
        chunk = ids[i:i + 100]

        def run(c=chunk):
            resp = get_with_retry('https://api.first.org/data/v1/epss', headers=UA, timeout=30,
                                  params={'cve': ','.join(c)})
            resp.raise_for_status()
            return {r['cve']: {'epss': float(r['epss']), 'percentile': float(r['percentile'])}
                    for r in resp.json().get('data', [])}
        out.update(R.EPSS.fetch(tuple(chunk), run))
    return out


def kev_catalog():
    def run():
        resp = get_with_retry(KEV_URL, headers=UA, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        return {
            'version': data.get('catalogVersion'),
            'released': data.get('dateReleased'),
            'count': data.get('count'),
            'items': {v['cveID']: {'vendor': v.get('vendorProject'), 'product': v.get('product'),
                                   'name': v.get('vulnerabilityName'), 'added': v.get('dateAdded'),
                                   'due': v.get('dueDate'),
                                   'ransomware': v.get('knownRansomwareCampaignUse'),
                                   'action': v.get('requiredAction')}
                      for v in data.get('vulnerabilities', [])},
        }
    return R.KEV.fetch('catalog', run)


def enrich(cve_ids, details=True, max_details=60):
    """Enrich a list of CVE IDs with CVSS (CVEDB), EPSS (FIRST) and KEV (CISA)."""
    ids = []
    for c in cve_ids:
        try:
            ids.append(normalise_cve(c))
        except ValueError:
            continue
    ids = sorted(set(ids))
    if not ids:
        return []
    items = {c: {'id': c, 'cvss': None, 'epss': None, 'kev': False, 'summary': ''} for c in ids}

    if details:
        def safe_detail(c):
            try:
                return cve_detail(c)
            except Exception:
                return None
        with ThreadPoolExecutor(max_workers=8) as pool:
            for c, d in zip(ids[:max_details], pool.map(safe_detail, ids[:max_details])):
                if d:
                    items[c].update({k: d.get(k) for k in ('summary', 'cvss', 'cvss_version',
                                                            'published', 'kev', 'epss')})
    try:
        for c, e in epss_scores(ids).items():
            if c in items:
                items[c]['epss'] = e['epss']
                items[c]['epss_percentile'] = e['percentile']
    except Exception:
        pass
    try:
        kev = kev_catalog()['items']
        for c in ids:
            if c in kev:
                items[c]['kev'] = True
                items[c]['kev_info'] = kev[c]
    except Exception:
        pass

    out = list(items.values())
    for item in out:
        item['severity'] = severity(item.get('cvss'))
        item['priority'] = priority(item)
    out.sort(key=sort_key)
    return out


def map_services(services, per_cpe=50):
    """Map scanner output (dicts with ``cpe`` lists) to prioritised CVEs."""
    cpes = sorted({c for s in services for c in (s.get('cpe') or []) if c.count(':') >= 4})
    mapping = []
    all_cves = {}
    for cpe in cpes:
        try:
            res = cves_for_cpe(cpe, limit=per_cpe)
        except Exception as e:
            mapping.append({'cpe': cpe, 'matched': None, 'count': 0, 'error': str(e)[:150]})
            continue
        mapping.append({'cpe': cpe, 'matched': res['cpe'], 'count': len(res['cves']), 'error': None})
        for cve in res['cves']:
            cve.setdefault('cpes', []).append(cpe)
            all_cves.setdefault(cve['id'], cve)
    try:
        kev = kev_catalog()['items']
    except Exception:
        kev = {}
    items = list(all_cves.values())
    for item in items:
        if item['id'] in kev:
            item['kev'] = True
            item['kev_info'] = kev[item['id']]
        item['severity'] = severity(item.get('cvss'))
        item['priority'] = priority(item)
    items.sort(key=sort_key)
    return {'cpes': mapping, 'cves': items, 'summary': summarise(items)}


def summarise(items):
    return {
        'total': len(items),
        'kev': sum(1 for i in items if i.get('kev')),
        'critical': sum(1 for i in items if i.get('severity') == 'critical'),
        'high': sum(1 for i in items if i.get('severity') == 'high'),
        'p1': sum(1 for i in items if i.get('priority') == 'P1'),
        'max_epss': max((i.get('epss') or 0 for i in items), default=0),
    }


def search(query):
    """Dispatch a free-text query: CVE id, CPE, or ``product version``."""
    q = (query or '').strip()
    if not q:
        raise ValueError('Masukkan CVE, CPE, atau produk + versi')
    if CVE_RE.match(q.upper()):
        item = cve_detail(q)
        extra = enrich([item['id']], details=False)
        if extra:
            item.update({k: v for k, v in extra[0].items() if v not in (None, '')})
        item['severity'] = severity(item.get('cvss'))
        item['priority'] = priority(item)
        return {'mode': 'cve', 'query': q, 'cve': item}
    if q.startswith('cpe:'):
        res = map_services([{'cpe': [q]}], per_cpe=200)
        return {'mode': 'cpe', 'query': q, **res}
    parts = q.split()
    if len(parts) >= 2:
        product = parts[0].lower()
        version = parts[-1]
        cpes = _cpes_for_product(product)
        matched = [c for c in cpes if c.split(':')[5] == version] or \
                  [c for c in cpes if c.split(':')[5].startswith(version)]
        if not matched:
            raise ValueError(f'CPE untuk {product} {version} tidak ditemukan di dictionary')
        res = map_services([{'cpe': [matched[0]]}], per_cpe=200)
        return {'mode': 'cpe', 'query': q, **res}
    raise ValueError('Gunakan format: CVE-YYYY-NNNN, cpe:2.3:..., atau "produk versi" (mis. openssh 7.4)')


def _cpes_for_product(product):
    def run():
        resp = get_with_retry('https://cvedb.shodan.io/cpes', headers=UA, timeout=30,
                              params={'product': product, 'limit': 1000})
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return resp.json().get('cpes', [])
    return R.CVEDB.fetch(('cpes', product), run)
