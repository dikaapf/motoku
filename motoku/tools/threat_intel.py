"""Threat-intel enrichment for IPs, domains, URLs and file hashes.

Every source returns the same normalised shape::

    {'source', 'category', 'status', 'verdict', 'summary', 'data', 'link'}

``status`` is ``ok`` | ``not_found`` | ``no_key`` | ``error`` and ``verdict`` is
``malicious`` | ``suspicious`` | ``clean`` | ``unknown``. Sources whose API key
is missing are reported (``no_key``) instead of silently skipped, so the UI can
show what would be gained by configuring them.
"""

import base64
import ipaddress
import os
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests

from services.providers import ProviderUnavailable, QuotaExceeded
from services.providers import registry as R

UA = {'User-Agent': 'Motoku-OSINT/1.3'}
TIMEOUT = 15
HASH_RE = re.compile(r'^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$')
VERDICT_ORDER = {'malicious': 0, 'suspicious': 1, 'clean': 2, 'unknown': 3}

SOURCES = {}


class NotFound(Exception):
    pass


def source(name, kinds, provider):
    def decorator(func):
        SOURCES[name] = {'func': func, 'kinds': kinds, 'provider': provider}
        return func
    return decorator


def classify(indicator):
    """Return ``(kind, normalised)`` where kind is ip/domain/url/hash."""
    value = (indicator or '').strip()
    if not value:
        raise ValueError('Indikator kosong')
    try:
        return 'ip', str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if HASH_RE.match(value):
        return 'hash', value.lower()
    if re.match(r'^https?://', value, re.I):
        if not urlparse(value).hostname:
            raise ValueError('URL tidak valid')
        return 'url', value
    if re.match(r'^(?=.{1,253}$)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9\-]{2,63}$', value.lower()):
        return 'domain', value.lower().rstrip('.')
    raise ValueError('Indikator harus IP, domain, URL, atau hash MD5/SHA1/SHA256')


def _result(name, status, verdict='unknown', summary='', data=None, link=None):
    return {'source': name, 'category': SOURCES[name]['provider'].category, 'status': status,
            'verdict': verdict, 'summary': summary, 'data': data or {}, 'link': link}


def _get(url, **kwargs):
    kwargs.setdefault('timeout', TIMEOUT)
    headers = dict(UA)
    headers.update(kwargs.pop('headers', {}) or {})
    resp = requests.get(url, headers=headers, **kwargs)
    if resp.status_code == 404:
        raise NotFound()
    if resp.status_code in (401, 403):
        raise ValueError(f'Ditolak ({resp.status_code}) — periksa API key')
    if resp.status_code == 429:
        raise ValueError('Rate limit provider')
    resp.raise_for_status()
    return resp


def _post(url, **kwargs):
    kwargs.setdefault('timeout', TIMEOUT)
    headers = dict(UA)
    headers.update(kwargs.pop('headers', {}) or {})
    resp = requests.post(url, headers=headers, **kwargs)
    if resp.status_code in (401, 403):
        raise ValueError(f'Ditolak ({resp.status_code}) — periksa API key')
    if resp.status_code == 429:
        raise ValueError('Rate limit provider')
    resp.raise_for_status()
    return resp


# ── 3.1 Attack surface ──
@source('internetdb', ('ip',), R.INTERNETDB)
def internetdb(kind, value):
    data = R.INTERNETDB.fetch(value, lambda: _get(f'https://internetdb.shodan.io/{value}').json())
    tags = data.get('tags', [])
    verdict = 'suspicious' if {'malware', 'c2', 'compromised'} & set(tags) else 'unknown'
    summary = f'{len(data.get("ports", []))} port, {len(data.get("vulns", []))} CVE'
    if tags:
        summary += ' · tag: ' + ', '.join(tags)
    return _result('internetdb', 'ok', verdict, summary, data, f'https://www.shodan.io/host/{value}')


@source('shodan', ('ip',), R.SHODAN)
def shodan(kind, value):
    key = R.SHODAN.api_key

    def run():
        d = _get(f'https://api.shodan.io/shodan/host/{value}', params={'key': key}).json()
        return {
            'org': d.get('org'), 'isp': d.get('isp'), 'asn': d.get('asn'), 'os': d.get('os'),
            'country': d.get('country_name'), 'hostnames': d.get('hostnames', []),
            'ports': d.get('ports', []), 'vulns': sorted(d.get('vulns', [])),
            'tags': d.get('tags', []), 'last_update': d.get('last_update'),
            'services': [{'port': s.get('port'), 'transport': s.get('transport'),
                          'product': s.get('product'), 'version': s.get('version'),
                          'cpe': s.get('cpe23') or s.get('cpe') or []}
                         for s in d.get('data', [])][:50],
        }
    data = R.SHODAN.fetch(value, run)
    return _result('shodan', 'ok', 'unknown',
                   f'{data.get("org") or "-"} · {len(data["ports"])} port · {len(data["vulns"])} CVE',
                   data, f'https://www.shodan.io/host/{value}')


@source('censys', ('ip',), R.CENSYS)
def censys(kind, value):
    api_id = os.environ.get('MOTOKU_CENSYS_API_ID', '').strip()
    if not api_id:
        raise ProviderUnavailable('Censys membutuhkan MOTOKU_CENSYS_API_ID dan MOTOKU_CENSYS_API_SECRET')

    def run():
        d = _get(f'https://search.censys.io/api/v2/hosts/{value}',
                 auth=(api_id, R.CENSYS.api_key)).json().get('result', {})
        return {
            'asn': (d.get('autonomous_system') or {}).get('asn'),
            'as_name': (d.get('autonomous_system') or {}).get('name'),
            'country': (d.get('location') or {}).get('country'),
            'services': [{'port': s.get('port'), 'service': s.get('service_name'),
                          'transport': s.get('transport_protocol')} for s in d.get('services', [])],
            'last_updated': d.get('last_updated_at'),
        }
    data = R.CENSYS.fetch(value, run)
    return _result('censys', 'ok', 'unknown', f'AS{data.get("asn")} {data.get("as_name") or ""} · '
                   f'{len(data["services"])} service', data, f'https://search.censys.io/hosts/{value}')


@source('fofa', ('ip', 'domain'), R.FOFA)
def fofa(kind, value):
    query = f'ip="{value}"' if kind == 'ip' else f'domain="{value}"'

    def run():
        d = _get('https://fofa.info/api/v1/search/all', params={
            'key': R.FOFA.api_key, 'size': 50, 'fields': 'host,ip,port,protocol,title,server',
            'qbase64': base64.b64encode(query.encode()).decode()}).json()
        if d.get('error'):
            raise ValueError(d.get('errmsg') or 'FOFA error')
        keys = ['host', 'ip', 'port', 'protocol', 'title', 'server']
        return {'size': d.get('size', 0), 'results': [dict(zip(keys, row)) for row in d.get('results', [])]}
    data = R.FOFA.fetch(query, run)
    return _result('fofa', 'ok', 'unknown', f'{data["size"]} hasil', data,
                   'https://fofa.info/result?qbase64=' + base64.b64encode(query.encode()).decode())


@source('netlas', ('ip', 'domain'), R.NETLAS)
def netlas(kind, value):
    def run():
        d = _get(f'https://app.netlas.io/api/host/{value}/',
                 headers={'X-API-Key': R.NETLAS.api_key}).json()
        return {'type': d.get('type'), 'ptr': d.get('ptr'), 'ports': [p.get('port') for p in d.get('ports', [])],
                'software': d.get('software', [])[:20], 'whois_org': ((d.get('whois') or {}).get('net') or {}).get('organization'),
                'domains_count': d.get('domains_count'), 'source': 'netlas'}
    data = R.NETLAS.fetch(value, run)
    return _result('netlas', 'ok', 'unknown', f'{len(data["ports"])} port', data,
                   f'https://app.netlas.io/host/{value}/')


# ── 3.2 Reputation & network ──
def _vt_path(kind, value):
    if kind == 'ip':
        return f'ip_addresses/{value}', f'https://www.virustotal.com/gui/ip-address/{value}'
    if kind == 'domain':
        return f'domains/{value}', f'https://www.virustotal.com/gui/domain/{value}'
    if kind == 'url':
        url_id = base64.urlsafe_b64encode(value.encode()).decode().strip('=')
        return f'urls/{url_id}', f'https://www.virustotal.com/gui/url/{url_id}'
    return f'files/{value}', f'https://www.virustotal.com/gui/file/{value}'


@source('virustotal', ('ip', 'domain', 'url', 'hash'), R.VIRUSTOTAL)
def virustotal(kind, value):
    path, link = _vt_path(kind, value)

    def run():
        attrs = _get(f'https://www.virustotal.com/api/v3/{path}',
                     headers={'x-apikey': R.VIRUSTOTAL.api_key}).json()['data']['attributes']
        return {
            'stats': attrs.get('last_analysis_stats', {}),
            'reputation': attrs.get('reputation'),
            'tags': attrs.get('tags', []),
            'categories': sorted(set((attrs.get('categories') or {}).values()))[:8],
            'as_owner': attrs.get('as_owner'), 'country': attrs.get('country'),
            'meaningful_name': attrs.get('meaningful_name'), 'type': attrs.get('type_description'),
            'last_analysis_date': attrs.get('last_analysis_date'),
        }
    data = R.VIRUSTOTAL.fetch((kind, value), run)
    stats = data['stats']
    mal, sus = stats.get('malicious', 0), stats.get('suspicious', 0)
    total = sum(stats.values()) or 0
    verdict = 'malicious' if mal >= 3 else 'suspicious' if (mal or sus) else 'clean' if total else 'unknown'
    return _result('virustotal', 'ok', verdict, f'{mal}/{total} engine menandai berbahaya', data, link)


@source('abuseipdb', ('ip',), R.ABUSEIPDB)
def abuseipdb(kind, value):
    def run():
        resp = _get('https://api.abuseipdb.com/api/v2/check',
                    params={'ipAddress': value, 'maxAgeInDays': 90},
                    headers={'Key': R.ABUSEIPDB.api_key, 'Accept': 'application/json'})
        rem, lim = resp.headers.get('X-RateLimit-Remaining'), resp.headers.get('X-RateLimit-Limit')
        if rem is not None:
            R.ABUSEIPDB.set_remote_quota(int(rem), int(lim) if lim else None, 'dari header API')
        d = resp.json()['data']
        return {k: d.get(k) for k in ('abuseConfidenceScore', 'totalReports', 'numDistinctUsers',
                                       'lastReportedAt', 'isp', 'usageType', 'domain', 'countryCode',
                                       'isTor', 'isWhitelisted')}
    data = R.ABUSEIPDB.fetch(value, run)
    score = data.get('abuseConfidenceScore') or 0
    verdict = 'malicious' if score >= 75 else 'suspicious' if score >= 25 else \
        'clean' if data.get('isWhitelisted') or data.get('totalReports') == 0 else 'unknown'
    return _result('abuseipdb', 'ok', verdict,
                   f'Skor abuse {score}% · {data.get("totalReports") or 0} laporan', data,
                   f'https://www.abuseipdb.com/check/{value}')


@source('greynoise', ('ip',), R.GREYNOISE)
def greynoise(kind, value):
    def run():
        headers = {'key': R.GREYNOISE.api_key} if R.GREYNOISE.api_key else {}
        resp = requests.get(f'https://api.greynoise.io/v3/community/{value}', headers={**UA, **headers},
                            timeout=TIMEOUT)
        if resp.status_code == 429:
            raise ValueError('Rate limit GreyNoise community')
        if resp.status_code not in (200, 404):
            resp.raise_for_status()
        return resp.json()
    data = R.GREYNOISE.fetch(value, run)
    cls = data.get('classification')
    verdict = {'malicious': 'malicious', 'suspicious': 'suspicious', 'benign': 'clean'}.get(cls, 'unknown')
    if data.get('riot'):
        verdict = 'clean'
    summary = data.get('message') or f'{cls or "-"} · {data.get("name") or ""}'
    if data.get('noise'):
        summary = f'Terlihat memindai internet ({cls}) · {data.get("name") or ""}'
    return _result('greynoise', 'ok', verdict, summary.strip(' ·'), data,
                   f'https://viz.greynoise.io/ip/{value}')


@source('ipinfo', ('ip',), R.IPINFO)
def ipinfo(kind, value):
    def run():
        params = {'token': R.IPINFO.api_key} if R.IPINFO.api_key else {}
        return _get(f'https://ipinfo.io/{value}/json', params=params).json()
    data = R.IPINFO.fetch(value, run)
    if data.get('bogon'):
        return _result('ipinfo', 'ok', 'unknown', 'Alamat privat/bogon', data)
    return _result('ipinfo', 'ok', 'unknown',
                   ', '.join(filter(None, [data.get('org'), data.get('city'), data.get('country')])),
                   data, f'https://ipinfo.io/{value}')


@source('ripestat', ('ip',), R.RIPESTAT)
def ripestat(kind, value):
    def run():
        d = _get('https://stat.ripe.net/data/prefix-overview/data.json',
                 params={'resource': value, 'sourceapp': 'motoku'}).json().get('data', {})
        asns = d.get('asns', [])
        rpki = None
        if asns and d.get('resource'):
            try:
                v = _get('https://stat.ripe.net/data/rpki-validation/data.json',
                         params={'resource': asns[0]['asn'], 'prefix': d['resource'],
                                 'sourceapp': 'motoku'}).json().get('data', {})
                rpki = v.get('status')
            except Exception:
                rpki = None
        return {'prefix': d.get('resource'), 'announced': d.get('announced'),
                'asns': [{'asn': a.get('asn'), 'holder': a.get('holder')} for a in asns],
                'block': (d.get('block') or {}).get('desc'), 'rpki': rpki}
    data = R.RIPESTAT.fetch(value, run)
    asn = data['asns'][0] if data['asns'] else {}
    summary = f'{data.get("prefix") or "-"} · AS{asn.get("asn", "?")} {asn.get("holder") or ""}'
    if data.get('rpki'):
        summary += f' · RPKI {data["rpki"]}'
    return _result('ripestat', 'ok', 'unknown', summary, data,
                   f'https://stat.ripe.net/app/launchpad/{value}')


# ── 3.3 Malware & phishing ──
@source('urlhaus', ('ip', 'domain', 'url'), R.URLHAUS)
def urlhaus(kind, value):
    def run():
        headers = {'Auth-Key': R.URLHAUS.api_key}
        if kind == 'url':
            return _post('https://urlhaus-api.abuse.ch/v1/url/', data={'url': value}, headers=headers).json()
        return _post('https://urlhaus-api.abuse.ch/v1/host/', data={'host': value}, headers=headers).json()
    data = R.URLHAUS.fetch((kind, value), run)
    if data.get('query_status') in ('no_results', 'invalid_host'):
        return _result('urlhaus', 'not_found', 'clean', 'Tidak ada di URLhaus')
    if kind == 'url':
        status = data.get('url_status')
        return _result('urlhaus', 'ok', 'malicious', f'URL malware ({status}) · {data.get("threat")}',
                       {k: data.get(k) for k in ('url_status', 'threat', 'tags', 'date_added')},
                       data.get('urlhaus_reference'))
    urls = data.get('urls', [])
    online = sum(1 for u in urls if u.get('url_status') == 'online')
    return _result('urlhaus', 'ok', 'malicious' if online else 'suspicious',
                   f'{len(urls)} URL malware tercatat ({online} online)',
                   {'url_count': data.get('url_count'), 'blacklists': data.get('blacklists'),
                    'urls': [{'url': u.get('url'), 'status': u.get('url_status'), 'threat': u.get('threat'),
                              'date_added': u.get('date_added')} for u in urls[:20]]},
                   data.get('urlhaus_reference'))


@source('malwarebazaar', ('hash',), R.MALWAREBAZAAR)
def malwarebazaar(kind, value):
    def run():
        return _post('https://mb-api.abuse.ch/api/v1/', data={'query': 'get_info', 'hash': value},
                     headers={'Auth-Key': R.MALWAREBAZAAR.api_key}).json()
    data = R.MALWAREBAZAAR.fetch(value, run)
    if data.get('query_status') != 'ok':
        return _result('malwarebazaar', 'not_found', 'unknown', 'Hash tidak ada di MalwareBazaar')
    s = (data.get('data') or [{}])[0]
    info = {k: s.get(k) for k in ('file_name', 'file_type', 'signature', 'tags', 'first_seen',
                                   'sha256_hash', 'reporter')}
    return _result('malwarebazaar', 'ok', 'malicious',
                   f'{s.get("signature") or "Malware"} · {s.get("file_type")} · {s.get("first_seen")}',
                   info, f'https://bazaar.abuse.ch/sample/{s.get("sha256_hash")}/')


@source('phishtank', ('url',), R.PHISHTANK)
def phishtank(kind, value):
    def run():
        body = {'url': value, 'format': 'json'}
        if R.PHISHTANK.api_key:
            body['app_key'] = R.PHISHTANK.api_key
        return _post('https://checkurl.phishtank.com/checkurl/', data=body,
                     headers={'User-Agent': 'phishtank/motoku-osint'}).json().get('results', {})
    data = R.PHISHTANK.fetch(value, run)
    if not data.get('in_database'):
        return _result('phishtank', 'not_found', 'unknown', 'Tidak ada di PhishTank')
    verified, valid = data.get('verified'), data.get('valid')
    if verified and valid:
        verdict, summary = 'malicious', 'Phishing terverifikasi'
    elif verified:
        verdict, summary = 'clean', 'Pernah dilaporkan, diverifikasi bukan phishing'
    else:
        verdict, summary = 'suspicious', 'Dilaporkan sebagai phishing (belum diverifikasi)'
    return _result('phishtank', 'ok', verdict, summary, data, data.get('phish_detail_page'))


@source('safebrowsing', ('domain', 'url'), R.SAFEBROWSING)
def safebrowsing(kind, value):
    url = value if kind == 'url' else f'http://{value}/'

    def run():
        body = {
            'client': {'clientId': 'motoku-osint', 'clientVersion': '1.3'},
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE',
                                'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes': ['ANY_PLATFORM'], 'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': url}],
            },
        }
        return _post('https://safebrowsing.googleapis.com/v4/threatMatches:find',
                     params={'key': R.SAFEBROWSING.api_key}, json=body).json()
    data = R.SAFEBROWSING.fetch(url, run)
    matches = data.get('matches', [])
    if not matches:
        return _result('safebrowsing', 'ok', 'clean', 'Tidak ada ancaman terdeteksi')
    types = sorted({m.get('threatType') for m in matches})
    return _result('safebrowsing', 'ok', 'malicious', 'Ditandai: ' + ', '.join(types), {'matches': matches},
                   f'https://transparencyreport.google.com/safe-browsing/search?url={url}')


@source('otx', ('ip', 'domain', 'url', 'hash'), R.OTX)
def otx(kind, value):
    section = {'ip': 'IPv6' if ':' in value else 'IPv4', 'domain': 'domain', 'url': 'url', 'hash': 'file'}[kind]

    def run():
        headers = {'X-OTX-API-KEY': R.OTX.api_key} if R.OTX.api_key else {}
        d = _get(f'https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general',
                 headers=headers).json()
        pulses = (d.get('pulse_info') or {}).get('pulses', [])
        return {'pulse_count': (d.get('pulse_info') or {}).get('count', 0),
                'pulses': [{'name': p.get('name'), 'created': p.get('created'), 'tags': p.get('tags', [])[:6]}
                           for p in pulses[:10]],
                'validation': [v.get('name') for v in d.get('validation', [])]}
    data = R.OTX.fetch((section, value), run)
    count = data['pulse_count']
    whitelisted = bool(data['validation'])
    if whitelisted:
        # Popular/benign indicators get whitelisted but still appear in many
        # pulses (as references or test samples) — only call it clean when no
        # pulse mentions it.
        verdict = 'clean' if count == 0 else 'unknown'
    else:
        verdict = 'suspicious' if count >= 3 else 'unknown'
    summary = f'{count} pulse threat intel' + (' · whitelisted OTX' if whitelisted else '')
    return _result('otx', 'ok', verdict, summary, data,
                   f'https://otx.alienvault.com/indicator/{section.lower()}/{value}')


# ── Orchestration ──
def _run_source(name, kind, value):
    entry = SOURCES[name]
    provider = entry['provider']
    if not provider.configured or (name == 'censys' and not os.environ.get('MOTOKU_CENSYS_API_ID')):
        return _result(name, 'no_key', summary=f'Set {provider.key_env}')
    try:
        return entry['func'](kind, value)
    except NotFound:
        return _result(name, 'not_found', summary='Tidak ada data')
    except ProviderUnavailable as e:
        return _result(name, 'no_key', summary=str(e))
    except QuotaExceeded as e:
        return _result(name, 'error', summary=str(e))
    except Exception as e:
        return _result(name, 'error', summary=str(e)[:200] or type(e).__name__)


def aggregate(results):
    rated = [r for r in results if r['status'] in ('ok', 'not_found')]
    verdicts = [r['verdict'] for r in rated]
    if 'malicious' in verdicts:
        verdict = 'malicious'
    elif 'suspicious' in verdicts:
        verdict = 'suspicious'
    elif 'clean' in verdicts:
        verdict = 'clean'
    else:
        verdict = 'unknown'
    return {
        'verdict': verdict,
        'malicious': verdicts.count('malicious'),
        'suspicious': verdicts.count('suspicious'),
        'clean': verdicts.count('clean'),
        'sources_ok': len(rated),
        'sources_no_key': sum(1 for r in results if r['status'] == 'no_key'),
        'sources_error': sum(1 for r in results if r['status'] == 'error'),
    }


def lookup(indicator, sources=None, include_unconfigured=True):
    kind, value = classify(indicator)
    names = [n for n, s in SOURCES.items() if kind in s['kinds'] and (not sources or n in sources)]
    with ThreadPoolExecutor(max_workers=max(1, len(names))) as pool:
        futures = {n: pool.submit(_run_source, n, kind, value) for n in names}
    results = [futures[n].result() for n in names]
    if not include_unconfigured:
        results = [r for r in results if r['status'] != 'no_key']
    results.sort(key=lambda r: (r['status'] != 'ok', VERDICT_ORDER.get(r['verdict'], 9), r['source']))
    cves = []
    for r in results:
        if r['source'] in ('internetdb', 'shodan') and r['status'] == 'ok':
            cves.extend(r['data'].get('vulns', []))
    return {
        'indicator': value,
        'kind': kind,
        'summary': aggregate(results),
        'results': results,
        'cves': sorted(set(cves)),
    }


def refresh_remote_quotas():
    """Ask providers with account endpoints for their real remaining quota."""
    refreshed = []
    if R.SHODAN.has_key:
        try:
            d = _get('https://api.shodan.io/api-info', params={'key': R.SHODAN.api_key}).json()
            R.SHODAN.set_remote_quota(d.get('query_credits'), None,
                                      f'query credits · scan credits {d.get("scan_credits")} · plan {d.get("plan")}')
            refreshed.append('shodan')
        except Exception:
            pass
    if R.VIRUSTOTAL.has_key:
        try:
            key = R.VIRUSTOTAL.api_key
            d = _get(f'https://www.virustotal.com/api/v3/users/{key}/overall_quotas',
                     headers={'x-apikey': key}).json().get('data', {})
            daily = d.get('api_requests_daily', {}).get('user', {})
            R.VIRUSTOTAL.set_remote_quota(
                (daily.get('allowed') or 0) - (daily.get('used') or 0), daily.get('allowed'), 'request harian')
            refreshed.append('virustotal')
        except Exception:
            pass
    if R.GITHUB.has_key:
        try:
            d = _get('https://api.github.com/rate_limit',
                     headers={'Authorization': f'Bearer {R.GITHUB.api_key}'}).json()
            cs = d.get('resources', {}).get('code_search', {})
            R.GITHUB.set_remote_quota(cs.get('remaining'), cs.get('limit'), 'code search / menit')
            refreshed.append('github')
        except Exception:
            pass
    return refreshed
