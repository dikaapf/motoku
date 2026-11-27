"""Exposed cloud storage and leaked-secret discovery.

* Bucket finder: derives candidate names from a keyword/domain and checks
  AWS S3, Google Cloud Storage and Azure Blob for existence and anonymous
  listing. Only object *names* are sampled; nothing is downloaded.
* GitHub secret scan: GitHub code search for the domain combined with secret
  keywords; matched fragments are classified and secret values are masked.
"""

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from xml.etree import ElementTree as ET

import requests

from services import resolver
from services.providers import registry as R

UA = {'User-Agent': 'Motoku-OSINT/1.3'}
TIMEOUT = 6
SUFFIXES = ['', 'backup', 'backups', 'bak', 'dev', 'development', 'staging', 'stage', 'prod',
            'production', 'test', 'qa', 'uat', 'assets', 'static', 'media', 'files', 'data',
            'uploads', 'upload', 'logs', 'public', 'private', 'images', 'img', 'cdn', 'web',
            'www', 'archive', 'internal', 'db', 'database', 'dump', 'export', 'reports', 'docs',
            'storage', 'bucket', 'app', 'api', 'content', 'downloads', 'shared', 'temp', 'tmp']
AZURE_CONTAINERS = ['public', 'files', 'backup', 'backups', 'images', 'data', 'assets',
                    'uploads', 'media', 'static', 'documents', '$web']
BUCKET_RE = re.compile(r'^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$')


def keyword_from(value):
    value = (value or '').strip().lower().split('://')[-1].split('/')[0]
    if value.startswith('www.'):
        value = value[4:]
    if '.' in value:
        parts = value.split('.')
        # strip 2-level public suffixes like co.id
        if len(parts) >= 3 and len(parts[-2]) <= 3:
            return parts[-3]
        return parts[-2]
    return re.sub(r'[^a-z0-9\-]', '', value)


def candidates(keyword, extra=(), limit=200):
    kw = keyword_from(keyword)
    if not kw or len(kw) < 2:
        raise ValueError('Keyword terlalu pendek')
    bases = [kw] + [keyword_from(e) for e in extra if e]
    names = []
    domainish = (keyword or '').strip().lower().split('://')[-1].split('/')[0]
    if domainish.startswith('www.'):
        domainish = domainish[4:]
    if '.' in domainish:
        # Buckets named after the exact domain (static website hosting) first.
        names.extend([domainish, domainish.replace('.', '-'), 'www.' + domainish])
    for base in dict.fromkeys(bases):
        for s in SUFFIXES:
            if not s:
                names.append(base)
                continue
            names.extend([f'{base}-{s}', f'{base}.{s}', f'{base}{s}', f'{s}-{base}'])
    out = [n for n in dict.fromkeys(names) if BUCKET_RE.match(n) and '..' not in n]
    return out[:limit]


def _listing_keys(xml_text, tag='Key', limit=10):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    keys = [el.text for el in root.iter() if el.tag.split('}')[-1] == tag and el.text]
    return keys[:limit]


def check_s3(name):
    url = f'https://s3.amazonaws.com/{name}'
    resp = requests.get(url, headers=UA, timeout=TIMEOUT, allow_redirects=False)
    body = resp.text[:50_000]
    if resp.status_code == 404 or 'NoSuchBucket' in body:
        return None
    region = resp.headers.get('x-amz-bucket-region')
    if resp.status_code in (301, 307) and region:
        # Bucket lives in another region: ask the regional endpoint.
        url = f'https://s3.{region}.amazonaws.com/{name}'
        resp = requests.get(url, headers=UA, timeout=TIMEOUT, allow_redirects=False)
        body = resp.text[:50_000]
    if resp.status_code == 200 and 'ListBucketResult' in body:
        return {'provider': 'AWS S3', 'name': name, 'status': 'public', 'region': region,
                'url': f'https://{name}.s3.amazonaws.com/' if '.' not in name else url,
                'sample': _listing_keys(body)}
    if resp.status_code in (301, 307, 400, 403) or 'AccessDenied' in body or 'PermanentRedirect' in body:
        return {'provider': 'AWS S3', 'name': name, 'status': 'private', 'region': region,
                'url': url, 'sample': []}
    return None


def check_gcs(name):
    url = f'https://storage.googleapis.com/{name}'
    resp = requests.get(url, headers=UA, timeout=TIMEOUT)
    body = resp.text[:50_000]
    if resp.status_code == 404:
        return None
    if resp.status_code == 200 and 'ListBucketResult' in body:
        return {'provider': 'Google Cloud Storage', 'name': name, 'status': 'public', 'url': url,
                'sample': _listing_keys(body)}
    if resp.status_code in (401, 403):
        return {'provider': 'Google Cloud Storage', 'name': name, 'status': 'private', 'url': url,
                'sample': []}
    return None


def check_azure(name):
    account = re.sub(r'[^a-z0-9]', '', name)
    if not 3 <= len(account) <= 24:
        return None
    host = f'{account}.blob.core.windows.net'
    if not resolver.resolve(host, 'A') and not resolver.resolve(host, 'CNAME'):
        return None
    public = []
    for container in AZURE_CONTAINERS:
        try:
            resp = requests.get(f'https://{host}/{container}', params={'restype': 'container', 'comp': 'list'},
                                headers=UA, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if resp.status_code == 200 and 'EnumerationResults' in resp.text:
            public.append({'container': container, 'sample': _listing_keys(resp.text, 'Name')})
    return {'provider': 'Azure Blob', 'name': account, 'status': 'public' if public else 'exists',
            'url': f'https://{host}/', 'containers': public,
            'sample': [f'{c["container"]}/{k}' for c in public for k in c['sample']][:10]}


CHECKS = {'s3': check_s3, 'gcs': check_gcs, 'azure': check_azure}


def find_buckets(keyword, providers=('s3', 'gcs', 'azure'), limit=200, workers=48, progress=None):
    names = candidates(keyword, limit=limit)
    azure_names = list(dict.fromkeys(re.sub(r'[^a-z0-9]', '', n) for n in names))

    tasks = []
    for p in providers:
        for n in (azure_names if p == 'azure' else names):
            tasks.append((p, n))

    def run():
        found, errors = [], 0
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(CHECKS[p], n): (p, n) for p, n in tasks}
            for i, fut in enumerate(as_completed(futures), 1):
                try:
                    hit = fut.result()
                except requests.RequestException:
                    hit = None
                    errors += 1
                if hit:
                    found.append(hit)
                if progress and i % 25 == 0:
                    progress(100 * i / len(tasks), f'{i}/{len(tasks)} nama dicek, {len(found)} ditemukan')
        order = {'public': 0, 'private': 1, 'exists': 2}
        found.sort(key=lambda b: (order.get(b['status'], 9), b['provider'], b['name']))
        return {'found': found, 'errors': errors}

    result = R.CLOUD_STORAGE.fetch((keyword_from(keyword), tuple(providers), limit), run)
    return {
        'keyword': keyword_from(keyword),
        'checked': len(tasks),
        'candidates': len(names),
        'public': sum(1 for b in result['found'] if b['status'] == 'public'),
        'buckets': result['found'],
        'errors': result['errors'],
    }


# ── GitHub secret scan ──
SECRET_PATTERNS = [
    ('AWS access key', re.compile(r'\b(AKIA|ASIA)[0-9A-Z]{16}\b')),
    ('Google API key', re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b')),
    ('GitHub token', re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b')),
    ('Slack token', re.compile(r'\bxox[baprs]-[A-Za-z0-9\-]{10,}\b')),
    ('Stripe key', re.compile(r'\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b')),
    ('Private key', re.compile(r'-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----')),
    ('JWT', re.compile(r'\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b')),
    ('Connection string', re.compile(r'\b(mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@/]+@[^\s"\']+', re.I)),
    ('Password assignment', re.compile(
        r'(?i)(?<![a-z0-9])(pass(?:word|wd)?|pwd|secret|api[_-]?key|token|auth)(?![a-z0-9])\s*[:=]\s*["\']?([^\s"\'<>,;]{6,})')),
]
SECRET_TERMS = ['password', 'secret', 'api_key', 'token']


def mask(value):
    value = str(value)
    if len(value) <= 8:
        return value[:2] + '…'
    return value[:4] + '…' + value[-2:] + f' ({len(value)} karakter)'


PLACEHOLDER_PREFIXES = ('process.env', 'os.environ', 'os.getenv', 'getenv(', 'env(', '${', '{{', '%(',
                        '<', 'config.', 'settings.', 'self.', 'this.', 'request.')


def _is_placeholder(value):
    v = value.lower()
    return v in ('null', 'none', 'true', 'false', 'undefined', 'changeme', 'password', 'example',
                 'xxxxxx', '******', 'your_password', 'yourpassword') or v.startswith(PLACEHOLDER_PREFIXES)


def classify_fragment(fragment):
    hits = []
    for label, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(fragment or ''):
            secret = m.group(2) if label == 'Password assignment' and m.lastindex and m.lastindex >= 2 else m.group(0)
            if label == 'Password assignment' and _is_placeholder(secret):
                continue
            hits.append({'type': label, 'masked': mask(secret)})
    return hits


def redact(fragment):
    text = fragment or ''
    for label, pattern in SECRET_PATTERNS:
        if label == 'Password assignment':
            text = pattern.sub(lambda m: m.group(0).replace(m.group(2), mask(m.group(2))), text)
        else:
            text = pattern.sub(lambda m: mask(m.group(0)), text)
    return text[:400]


def github_leaks(domain, terms=None, per_query=20):
    if not R.GITHUB.configured:
        return {'status': 'no_key', 'message': f'Set {R.GITHUB.key_env} untuk GitHub code search',
                'results': []}
    domain = (domain or '').strip().lower().split('://')[-1].split('/')[0]
    if '.' not in domain:
        raise ValueError('Masukkan domain untuk GitHub scan')
    terms = terms or SECRET_TERMS
    headers = {**UA, 'Authorization': f'Bearer {R.GITHUB.api_key}',
               'Accept': 'application/vnd.github.text-match+json',
               'X-GitHub-Api-Version': '2022-11-28'}
    seen = {}
    errors = []
    for i, term in enumerate(terms):
        query = f'"{domain}" {term}'

        def run(q=query):
            resp = requests.get('https://api.github.com/search/code', headers=headers, timeout=20,
                                params={'q': q, 'per_page': per_query})
            rem, lim = resp.headers.get('X-RateLimit-Remaining'), resp.headers.get('X-RateLimit-Limit')
            if rem is not None:
                R.GITHUB.set_remote_quota(int(rem), int(lim) if lim else None, 'code search / menit')
            if resp.status_code in (403, 429):
                raise ValueError('Rate limit GitHub code search (10/menit)')
            if resp.status_code == 401:
                raise ValueError('Token GitHub tidak valid')
            resp.raise_for_status()
            items = []
            for it in resp.json().get('items', []):
                fragments = [m.get('fragment', '') for m in it.get('text_matches', [])]
                items.append({'repo': it['repository']['full_name'], 'path': it['path'],
                              'url': it['html_url'],
                              'findings': [h for f in fragments for h in classify_fragment(f)],
                              'snippets': [redact(f) for f in fragments][:3]})
            return items
        try:
            for item in R.GITHUB.fetch(query, run):
                key = item['url']
                if key in seen:
                    seen[key]['terms'].append(term)
                else:
                    seen[key] = dict(item, terms=[term])
        except Exception as e:
            errors.append(f'{term}: {e}')
            if 'Rate limit' in str(e):
                break
        if i < len(terms) - 1:
            time.sleep(1)
    results = sorted(seen.values(), key=lambda r: (-len(r['findings']), r['repo']))
    return {'status': 'ok', 'domain': domain, 'results': results,
            'with_secrets': sum(1 for r in results if r['findings']), 'errors': errors}
