"""HTTP probe: status, title, server, redirect chain, favicon hash, screenshot."""

import base64
import hashlib
import html
import os
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

UA = ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/124.0 Safari/537.36 Motoku-OSINT/1.2')
TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.I | re.S)
ICON_RE = re.compile(r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]*>', re.I)
HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)
SCREENSHOT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'screenshots')


def favicon_hash(content):
    """Shodan-compatible favicon hash (mmh3 of base64 with newlines)."""
    import mmh3

    return mmh3.hash(base64.encodebytes(content))


def _title(body):
    m = TITLE_RE.search(body or '')
    if not m:
        return ''
    return re.sub(r'\s+', ' ', html.unescape(m.group(1))).strip()[:200]


def _favicon_url(base_url, body):
    for tag in ICON_RE.findall(body or ''):
        href = HREF_RE.search(tag)
        if href and not href.group(1).startswith('data:'):
            return urljoin(base_url, href.group(1))
    return urljoin(base_url, '/favicon.ico')


def fetch_favicon(base_url, body='', timeout=8):
    url = _favicon_url(base_url, body)
    try:
        resp = requests.get(url, headers={'User-Agent': UA}, timeout=timeout, verify=False)
    except requests.RequestException:
        return None
    if resp.status_code != 200 or not resp.content or len(resp.content) > 2_000_000:
        return None
    ctype = resp.headers.get('Content-Type', '')
    if 'html' in ctype:
        return None
    mmh = favicon_hash(resp.content)
    return {
        'url': url,
        'mmh3': mmh,
        'md5': hashlib.md5(resp.content).hexdigest(),
        'size': len(resp.content),
        'shodan_query': f'http.favicon.hash:{mmh}',
    }


def probe(host, timeout=8, with_favicon=False):
    """Probe ``host`` over HTTPS then HTTP; returns the first that answers."""
    result = {'host': host, 'alive': False}
    for scheme in ('https', 'http'):
        url = host if '://' in host else f'{scheme}://{host}'
        try:
            resp = requests.get(url, headers={'User-Agent': UA}, timeout=timeout,
                                allow_redirects=True, verify=False, stream=True)
            body = resp.raw.read(300_000, decode_content=True).decode(resp.encoding or 'utf-8',
                                                                         errors='replace')
            resp.close()
        except (requests.RequestException, urllib3.exceptions.HTTPError, OSError):
            if '://' in host:
                break
            continue
        result.update({
            'alive': True,
            'url': url,
            'final_url': resp.url,
            'status': resp.status_code,
            'title': _title(body),
            'server': resp.headers.get('Server', ''),
            'powered_by': resp.headers.get('X-Powered-By', ''),
            'content_type': resp.headers.get('Content-Type', '').split(';')[0],
            'content_length': len(body),
            'redirects': [r.headers.get('Location', '') for r in resp.history][:5],
            'https': resp.url.startswith('https://'),
        })
        if with_favicon:
            result['favicon'] = fetch_favicon(resp.url, body, timeout)
        break
    return result


def probe_many(hosts, workers=24, progress=None, with_favicon=False):
    out = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(probe, h, 8, with_favicon): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            try:
                out.append(fut.result())
            except Exception:
                out.append({'host': futures[fut], 'alive': False})
            if progress:
                progress(i, len(hosts))
    out.sort(key=lambda r: (not r['alive'], r['host']))
    return out


# ── Screenshots ──
def screenshot_backend():
    try:
        import playwright.sync_api  # noqa: F401

        return 'playwright'
    except ImportError:
        pass
    if _chromium_binary():
        return 'chromium'
    return None


def _chromium_binary():
    explicit = os.environ.get('MOTOKU_CHROMIUM_PATH', '').strip()
    if explicit and os.path.exists(explicit):
        return explicit
    for name in ('chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable'):
        path = shutil.which(name)
        if path:
            return path
    return None


def _safe_name(url):
    parsed = urlparse(url)
    stem = re.sub(r'[^a-z0-9.\-]', '_', (parsed.hostname or 'page').lower())
    return f'{stem}-{hashlib.sha1(url.encode()).hexdigest()[:8]}.png'


def screenshot(url, timeout=45):
    """Save a 1280x800 PNG of ``url``; returns the file name or ``None``."""
    backend = screenshot_backend()
    if backend is None:
        return None
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    name = _safe_name(url)
    path = os.path.join(SCREENSHOT_DIR, name)

    if backend == 'playwright':
        from playwright.sync_api import sync_playwright

        try:
            with sync_playwright() as p:
                launch = {'args': ['--no-sandbox']}
                binary = _chromium_binary()
                if binary:
                    launch['executable_path'] = binary
                browser = p.chromium.launch(**launch)
                page = browser.new_page(viewport={'width': 1280, 'height': 800},
                                        ignore_https_errors=True)
                page.goto(url, timeout=timeout * 1000, wait_until='load')
                page.screenshot(path=path)
                browser.close()
            return name
        except Exception:
            return None

    with tempfile.TemporaryDirectory(prefix='motoku-chrome-') as profile:
        cmd = [
            _chromium_binary(), '--headless=new', '--no-sandbox', '--disable-gpu',
            '--hide-scrollbars', '--ignore-certificate-errors', '--mute-audio',
            f'--user-data-dir={profile}', '--window-size=1280,800',
            f'--screenshot={path}', '--virtual-time-budget=8000', url,
        ]
        try:
            subprocess.run(cmd, timeout=timeout, capture_output=True, check=False)
        except (subprocess.TimeoutExpired, OSError):
            return None
    return name if os.path.exists(path) and os.path.getsize(path) > 0 else None
