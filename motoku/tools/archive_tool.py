"""Historical & passive web intel: Wayback CDX, urlscan.io, favicon hash."""

import os
import re
from collections import Counter
from urllib.parse import urlparse

import requests

from services.http import get_with_retry
from services.providers.registry import URLSCAN, WAYBACK
from tools import http_probe

UA = {'User-Agent': 'Motoku-OSINT/1.2'}
INTERESTING = re.compile(
    r'(\.env|\.git/|\.sql|\.bak|\.old|\.zip|\.tar|\.gz|\.log|\.conf|\.cfg|\.ini|\.ya?ml|'
    r'\.json|\.xml|\.php\?|wp-admin|wp-config|phpmyadmin|/admin|/login|/api/|/graphql|'
    r'swagger|/debug|/backup|/config|token=|apikey=|api_key=|password=|secret=)', re.I)


def wayback(domain, limit=2000):
    def run():
        resp = get_with_retry('https://web.archive.org/cdx/search/cdx', params={
            'url': f'{domain}/*', 'output': 'json', 'fl': 'timestamp,original,statuscode,mimetype',
            'collapse': 'urlkey', 'limit': str(limit),
        }, headers=UA, timeout=45)
        resp.raise_for_status()
        rows = resp.json() if resp.text.strip() else []
        return [dict(zip(rows[0], r)) for r in rows[1:]] if rows else []

    rows = WAYBACK.fetch(domain, run)
    exts = Counter()
    hosts = Counter()
    interesting = []
    years = Counter()
    for r in rows:
        url = r.get('original', '')
        parsed = urlparse(url)
        hosts[(parsed.hostname or '').lower()] += 1
        ext = os.path.splitext(parsed.path)[1].lower()
        if ext:
            exts[ext] += 1
        years[r.get('timestamp', '')[:4]] += 1
        if INTERESTING.search(url) and len(interesting) < 200:
            interesting.append({'url': url, 'timestamp': r.get('timestamp'),
                                'status': r.get('statuscode'),
                                'archive': f'https://web.archive.org/web/{r.get("timestamp")}/{url}'})
    return {
        'total': len(rows),
        'truncated': len(rows) >= limit,
        'first': min((r['timestamp'] for r in rows), default=None),
        'last': max((r['timestamp'] for r in rows), default=None),
        'by_year': sorted(years.items()),
        'extensions': exts.most_common(15),
        'hosts': hosts.most_common(20),
        'interesting': interesting,
        'sample': [r['original'] for r in rows[:100]],
    }


def urlscan(domain, size=50):
    def run():
        headers = dict(UA)
        key = os.environ.get('MOTOKU_URLSCAN_API_KEY', '').strip()
        if key:
            headers['API-Key'] = key
        resp = requests.get('https://urlscan.io/api/v1/search/',
                            params={'q': f'domain:{domain}', 'size': str(size)},
                            headers=headers, timeout=20)
        if resp.status_code == 429:
            raise ValueError('urlscan.io rate limit')
        resp.raise_for_status()
        out = []
        for r in resp.json().get('results', []):
            page = r.get('page', {})
            task = r.get('task', {})
            out.append({
                'url': page.get('url') or task.get('url'),
                'domain': page.get('domain'),
                'ip': page.get('ip'),
                'asn': page.get('asnname'),
                'country': page.get('country'),
                'server': page.get('server'),
                'status': page.get('status'),
                'title': page.get('title'),
                'time': task.get('time'),
                'result': r.get('result'),
                'screenshot': r.get('screenshot'),
            })
        return out

    results = URLSCAN.fetch(domain, run)
    return {
        'total': len(results),
        'results': results,
        'ips': Counter(r['ip'] for r in results if r.get('ip')).most_common(10),
        'servers': Counter(r['server'] for r in results if r.get('server')).most_common(10),
    }


def favicon(domain):
    probe = http_probe.probe(domain, with_favicon=True)
    return (probe or {}).get('favicon')


def investigate(domain):
    domain = (domain or '').strip().lower().split('://')[-1].split('/')[0]
    if not domain or '.' not in domain:
        raise ValueError('Domain tidak valid')
    report = {'domain': domain}
    for key, func in (('wayback', wayback), ('urlscan', urlscan), ('favicon', favicon)):
        try:
            report[key] = func(domain)
            report[f'{key}_error'] = None
        except Exception as e:
            report[key] = None
            report[f'{key}_error'] = str(e)[:200] or type(e).__name__
    return report
