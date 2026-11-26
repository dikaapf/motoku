"""Username enumeration powered by the WhatsMyName dataset.

Dataset: https://github.com/WebBreacher/WhatsMyName (CC BY-SA 4.0). A copy is
bundled in ``data/wmn-data.json`` and can be refreshed with
:func:`update_dataset`. Sites are checked concurrently; a hit requires both the
"exists" status code and the "exists" marker string, and must not contain the
"missing" marker, which is far more accurate than a bare HTTP 200 check.
"""

import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import requests

from services.providers.registry import WHATSMYNAME

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
DATASET_PATH = os.path.join(DATA_DIR, 'wmn-data.json')
DATASET_URL = 'https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json'

NSFW_CATEGORY = 'xx NSFW xx'
DEFAULT_TIMEOUT = 8
DEFAULT_WORKERS = 48
USER_AGENT = (
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/124.0 Safari/537.36'
)
USERNAME_ALLOWED = re.compile(r'^[A-Za-z0-9._\-]{1,64}$')

_dataset_cache = {'mtime': None, 'data': None}


def load_dataset(path=None):
    path = path or DATASET_PATH
    if not os.path.exists(path):
        return {'sites': [], 'categories': []}
    mtime = os.path.getmtime(path)
    if _dataset_cache['mtime'] == mtime and _dataset_cache['data'] is not None:
        return _dataset_cache['data']
    with open(path, encoding='utf-8') as fh:
        data = json.load(fh)
    _dataset_cache.update(mtime=mtime, data=data)
    return data


def dataset_info():
    data = load_dataset()
    sites = [s for s in data.get('sites', []) if s.get('valid', True) is not False]
    updated = None
    if os.path.exists(DATASET_PATH):
        updated = time.strftime('%Y-%m-%d %H:%M', time.localtime(os.path.getmtime(DATASET_PATH)))
    return {
        'total_sites': len(sites),
        'categories': sorted(data.get('categories', [])),
        'updated': updated,
    }


def update_dataset(timeout=30):
    """Download the latest dataset; returns the number of sites."""
    resp = requests.get(DATASET_URL, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data.get('sites'), list) or not data['sites']:
        raise ValueError('Dataset WhatsMyName tidak valid')
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = DATASET_PATH + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(data, fh)
    os.replace(tmp, DATASET_PATH)
    return len(data['sites'])


def select_sites(categories=None, include_nsfw=False):
    sites = []
    for site in load_dataset().get('sites', []):
        if site.get('valid', True) is False:
            continue
        cat = site.get('cat', 'misc')
        if cat == NSFW_CATEGORY and not include_nsfw:
            continue
        if categories and cat not in categories:
            continue
        sites.append(site)
    return sites


def _prepare_username(site, username):
    bad = site.get('strip_bad_char')
    if bad:
        for ch in bad:
            username = username.replace(ch, '')
    return username


def evaluate(site, status_code, body):
    """Classify a response as ``found``, ``not_found`` or ``unknown``."""
    e_code = site.get('e_code')
    e_string = site.get('e_string') or ''
    m_code = site.get('m_code')
    m_string = site.get('m_string') or ''

    if status_code == e_code and (not e_string or e_string in body):
        if m_string and m_string in body and m_code == e_code:
            return 'not_found'
        return 'found'
    if status_code == m_code and (not m_string or m_string in body):
        return 'not_found'
    if m_string and m_string in body:
        return 'not_found'
    # A plain 404/410 is an unambiguous "no such account" signal even when the
    # dataset expects a different missing code. Anything else (403 bot walls,
    # 429 rate limits, 200 pages without either marker) stays uncertain.
    if status_code in (404, 410) and e_code not in (404, 410):
        return 'not_found'
    return 'unknown'


def check_site(site, username, timeout=DEFAULT_TIMEOUT, session=None):
    account = quote(_prepare_username(site, username), safe='')
    url = site['uri_check'].replace('{account}', account)
    pretty = (site.get('uri_pretty') or site['uri_check']).replace('{account}', account)

    headers = {'User-Agent': USER_AGENT, 'Accept-Language': 'en-US,en;q=0.8'}
    headers.update(site.get('headers') or {})
    http = session or requests

    result = {
        'name': site['name'],
        'category': site.get('cat', 'misc'),
        'url': pretty,
        'status': 'unknown',
        'http_code': None,
        'error': None,
    }
    started = time.monotonic()
    try:
        if site.get('post_body'):
            body = site['post_body'].replace('{account}', account)
            resp = http.post(url, data=body, headers=headers, timeout=timeout, allow_redirects=True)
        else:
            resp = http.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        text = resp.text[:500_000]
        result['http_code'] = resp.status_code
        result['status'] = evaluate(site, resp.status_code, text)
        if result['status'] == 'unknown' and resp.status_code in (401, 403, 429, 503):
            result['error'] = 'Diblokir/rate limit' if resp.status_code != 401 else 'Butuh login'
    except requests.RequestException as e:
        result['error'] = type(e).__name__
    result['elapsed_ms'] = int((time.monotonic() - started) * 1000)
    return result


def search(username, categories=None, include_nsfw=False,
           timeout=DEFAULT_TIMEOUT, workers=DEFAULT_WORKERS):
    username = (username or '').strip().lstrip('@')
    if not USERNAME_ALLOWED.match(username):
        raise ValueError('Username hanya boleh berisi huruf, angka, titik, garis bawah, atau strip')

    sites = select_sites(categories, include_nsfw)
    if not sites:
        raise ValueError('Dataset WhatsMyName belum tersedia. Jalankan update dataset.')

    key = {'u': username.lower(), 'c': sorted(categories or []), 'n': include_nsfw}

    def run():
        started = time.monotonic()
        results = []
        with requests.Session() as session:
            adapter = requests.adapters.HTTPAdapter(pool_connections=workers, pool_maxsize=workers)
            session.mount('https://', adapter)
            session.mount('http://', adapter)
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [pool.submit(check_site, s, username, timeout, session) for s in sites]
                for fut in as_completed(futures):
                    results.append(fut.result())
        results.sort(key=lambda r: (r['status'] != 'found', r['category'], r['name'].lower()))
        counts = {'found': 0, 'not_found': 0, 'unknown': 0}
        for r in results:
            counts[r['status']] += 1
        return {
            'username': username,
            'checked': len(results),
            'counts': counts,
            'elapsed_s': round(time.monotonic() - started, 1),
            'results': results,
        }

    return WHATSMYNAME.fetch(key, run)
