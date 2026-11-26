"""Multi-source subdomain enumeration.

Passive sources: crt.sh, CertSpotter, AlienVault OTX and HackerTarget, plus a
small DNS brute force. Results are resolved concurrently, wildcard DNS is
detected and filtered, and every host is labelled with the sources that
reported it.
"""

import os
import re
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from services import resolver
from services.http import get_with_retry
from services.providers.registry import CERTSPOTTER, CRTSH, HACKERTARGET, OTX

UA = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Motoku-OSINT/1.2'}

COMMON_SUBDOMAINS = sorted({
    'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'cdn', 'dev', 'test', 'staging',
    'vpn', 'remote', 'webmail', 'smtp', 'pop3', 'imap', 'mysql', 'db', 'database',
    'backup', 'beta', 'demo', 'forum', 'help', 'intranet', 'portal', 'secure',
    'status', 'support', 'wiki', 'app', 'mobile', 'm', 'shop', 'store', 'assets',
    'download', 'docs', 'info', 'news', 'partner', 'old', 'new', 'manager', 'ns1',
    'ns2', 'ns3', 'ns4', 'mx', 'mx1', 'mx2', 'gateway', 'firewall', 'proxy',
    'tracking', 'analytics', 'stats', 'chat', 'community', 'email', 'exchange',
    'host', 'server', 'web', 'cloud', 'login', 'signup', 'register', 'auth', 'sso',
    'pay', 'payment', 'billing', 'invoice', 'redis', 'queue', 'monitor', 'logs',
    'jenkins', 'git', 'ci', 'image', 'img', 'static', 'media', 'video', 'corp',
    'office', 'lb', 'node1', 'node2', 'dns1', 'dns2', 'mail1', 'mail2', 'pop',
    'owa', 'autodiscover', 'confluence', 'jira', 'svn', 'gitlab', 'docker', 'k8s',
    'grafana', 'prometheus', 'kibana', 'elastic', 'nexus', 'sonar', 'swagger',
    'developer', 'sandbox', 'stage', 'preprod', 'prod', 'uat', 'qa', 'internal',
    'edge', 'origin', 'files', 'cpanel', 'whm', 'webdisk', 'ns', 'mta-sts',
})

SOURCE_FUNCS = {}


def source(name):
    def decorator(func):
        SOURCE_FUNCS[name] = func
        return func
    return decorator


def clean_domain(domain):
    domain = (domain or '').strip().lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0].split(':')[0].rstrip('.')
    if domain.startswith('*.'):
        domain = domain[2:]
    if not re.match(r'^[a-z0-9.\-]+\.[a-z0-9\-]{2,}$', domain):
        raise ValueError('Domain tidak valid')
    return domain


def _filter(names, domain):
    out = set()
    suffix = '.' + domain
    for raw in names:
        name = (raw or '').strip().lower().rstrip('.')
        if name.startswith('*.'):
            name = name[2:]
        if name.endswith(suffix) and name != domain and '*' not in name and ' ' not in name:
            if re.match(r'^[a-z0-9_.\-]+$', name):
                out.add(name)
    return out


@source('crt.sh')
def from_crtsh(domain):
    def run():
        # crt.sh is frequently overloaded and answers 404/502 transiently.
        resp = get_with_retry('https://crt.sh/', params={'q': f'%.{domain}', 'output': 'json'},
                              headers=UA, timeout=30, retry_statuses=(404, 429, 500, 502, 503, 504))
        resp.raise_for_status()
        names = []
        for entry in resp.json() if resp.text.strip() else []:
            names.extend((entry.get('name_value') or '').split('\n'))
        return sorted(_filter(names, domain))
    return set(CRTSH.fetch(domain, run))


@source('certspotter')
def from_certspotter(domain):
    def run():
        headers = dict(UA)
        key = os.environ.get('MOTOKU_CERTSPOTTER_API_KEY', '').strip()
        if key:
            headers['Authorization'] = f'Bearer {key}'
        resp = requests.get('https://api.certspotter.com/v1/issuances',
                            params={'domain': domain, 'include_subdomains': 'true',
                                    'expand': 'dns_names'},
                            headers=headers, timeout=20)
        if resp.status_code == 429:
            raise ValueError('CertSpotter rate limit')
        resp.raise_for_status()
        names = [n for item in resp.json() for n in item.get('dns_names', [])]
        return sorted(_filter(names, domain))
    return set(CERTSPOTTER.fetch(domain, run))


@source('otx')
def from_otx(domain):
    def run():
        headers = dict(UA)
        key = os.environ.get('MOTOKU_OTX_API_KEY', '').strip()
        if key:
            headers['X-OTX-API-KEY'] = key
        resp = get_with_retry(
            f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns',
            headers=headers, timeout=20, attempts=2, backoff=3)
        resp.raise_for_status()
        names = [r.get('hostname') for r in resp.json().get('passive_dns', [])]
        return sorted(_filter(names, domain))
    return set(OTX.fetch(domain, run))


@source('hackertarget')
def from_hackertarget(domain):
    def run():
        resp = requests.get('https://api.hackertarget.com/hostsearch/',
                            params={'q': domain}, headers=UA, timeout=20)
        resp.raise_for_status()
        text = resp.text.strip()
        if 'API count exceeded' in text or text.startswith('error'):
            raise ValueError(text[:100])
        names = [line.split(',')[0] for line in text.splitlines() if ',' in line]
        return sorted(_filter(names, domain))
    return set(HACKERTARGET.fetch(domain, run))


def resolve_host(name):
    """Return ``{'a': [...], 'aaaa': [...], 'cname': [...]}`` for ``name``."""
    return {
        'cname': [c.rstrip('.') for c in resolver.resolve(name, 'CNAME')],
        'a': resolver.resolve(name, 'A'),
        'aaaa': resolver.resolve(name, 'AAAA'),
    }


def detect_wildcard(domain):
    """Resolve random labels; if they answer, the zone has wildcard DNS."""
    ips = set()
    for _ in range(2):
        label = 'motoku-' + secrets.token_hex(6)
        ips |= set(resolver.resolve(f'{label}.{domain}', 'A'))
    return {'enabled': bool(ips), 'ips': sorted(ips)}


def brute_force(domain, wildcard_ips=(), workers=32):
    found = set()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(resolver.resolve, f'{w}.{domain}', 'A'): w for w in COMMON_SUBDOMAINS}
        for fut in as_completed(futures):
            ips = set(fut.result() or [])
            if ips and not ips <= set(wildcard_ips):
                found.add(f'{futures[fut]}.{domain}')
    return found


def enumerate_subdomains(domain, sources=None, brute=True, resolve=True, progress=None, workers=32):
    """Collect, resolve and de-duplicate subdomains for ``domain``.

    ``progress(percent, message)`` is called as each stage completes.
    """
    domain = clean_domain(domain)
    report = progress or (lambda pct, msg: None)
    sources = sources or list(SOURCE_FUNCS)

    by_name = {}
    source_stats = {}

    def add(names, src):
        for name in names:
            by_name.setdefault(name, set()).add(src)

    report(2, 'Cek wildcard DNS')
    wildcard = detect_wildcard(domain)

    report(5, f'Query {len(sources)} sumber pasif')
    with ThreadPoolExecutor(max_workers=len(sources) or 1) as pool:
        futures = {pool.submit(SOURCE_FUNCS[s], domain): s for s in sources if s in SOURCE_FUNCS}
        done = 0
        for fut in as_completed(futures):
            src = futures[fut]
            done += 1
            try:
                names = fut.result()
                add(names, src)
                source_stats[src] = {'count': len(names), 'error': None}
            except Exception as e:
                source_stats[src] = {'count': 0, 'error': str(e)[:150] or type(e).__name__}
            report(5 + 35 * done // max(1, len(futures)),
                   f'{src}: {source_stats[src]["count"]} host'
                   + (f' (error: {source_stats[src]["error"]})' if source_stats[src]['error'] else ''))

    if brute:
        report(42, f'DNS brute force {len(COMMON_SUBDOMAINS)} kata')
        names = brute_force(domain, wildcard['ips'], workers)
        add(names, 'bruteforce')
        source_stats['bruteforce'] = {'count': len(names), 'error': None}

    hosts = []
    names = sorted(by_name)
    if resolve and names:
        report(55, f'Resolve {len(names)} host')
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(resolve_host, n): n for n in names}
            records = {}
            for i, fut in enumerate(as_completed(futures), 1):
                records[futures[fut]] = fut.result()
                if i % 25 == 0:
                    report(55 + 35 * i // len(names), f'Resolve {i}/{len(names)}')
    else:
        records = {n: {'a': [], 'aaaa': [], 'cname': []} for n in names}

    wildcard_ips = set(wildcard['ips'])
    for name in names:
        rec = records.get(name, {'a': [], 'aaaa': [], 'cname': []})
        alive = bool(rec['a'] or rec['aaaa'] or rec['cname'])
        wildcard_match = bool(wildcard_ips) and bool(rec['a']) and set(rec['a']) <= wildcard_ips
        hosts.append({
            'name': name,
            'sources': sorted(by_name[name]),
            'a': rec['a'],
            'aaaa': rec['aaaa'],
            'cname': rec['cname'],
            'alive': alive,
            'wildcard': wildcard_match and 'bruteforce' in by_name[name] and len(by_name[name]) == 1,
        })

    report(95, 'Menyusun hasil')
    return {
        'domain': domain,
        'wildcard': wildcard,
        'sources': source_stats,
        'total': len(hosts),
        'alive': sum(1 for h in hosts if h['alive']),
        'hosts': hosts,
        'mx_records': _mx(domain),
        'ns_records': [n.rstrip('.') for n in resolver.resolve(domain, 'NS')],
    }


def _mx(domain):
    out = []
    for raw in resolver.resolve(domain, 'MX'):
        prio, _, host = raw.partition(' ')
        if prio.isdigit():
            out.append({'priority': int(prio), 'host': host.rstrip('.')})
    return sorted(out, key=lambda r: r['priority'])


# ── Graph (vis-network) ──
_STYLE = {
    'domain': {'shape': 'box', 'font': {'size': 20, 'face': 'monospace', 'color': '#00ff88'},
               'borderWidth': 3, 'color': {'background': '#0d2810', 'border': '#00ff88'}},
    'subdomain': {'font': {'face': 'monospace', 'color': '#88ddff'},
                  'color': {'background': '#0a1a28', 'border': '#00ccff'}},
    'takeover': {'font': {'face': 'monospace', 'color': '#ff6666'},
                 'color': {'background': '#3a0a0a', 'border': '#ff3333'}, 'borderWidth': 3},
    'ip': {'shape': 'ellipse', 'font': {'face': 'monospace', 'color': '#ffaa44'},
           'color': {'background': '#281a0a', 'border': '#ff8800'}},
    'cname': {'shape': 'ellipse', 'font': {'face': 'monospace', 'color': '#cccccc', 'size': 10},
              'color': {'background': '#1a1a1a', 'border': '#888888'}},
    'mx': {'shape': 'diamond', 'font': {'face': 'monospace', 'color': '#ff6666'},
           'color': {'background': '#281010', 'border': '#ff4444'}},
    'ns': {'shape': 'triangle', 'font': {'face': 'monospace', 'color': '#dd88ff'},
           'color': {'background': '#1a1030', 'border': '#aa66ff'}},
}


def build_graph(data, takeover_hosts=(), max_hosts=150):
    domain = data['domain']
    nodes, edges, seen = [], [], set()

    def node(node_id, label, group):
        if node_id not in seen:
            seen.add(node_id)
            nodes.append(dict(_STYLE[group], id=node_id, label=label, group=group))

    def edge(a, b, label, color, dashes=False):
        edges.append({'from': a, 'to': b, 'label': label, 'dashes': dashes,
                      'color': {'color': color, 'opacity': 0.6}, 'width': 1.5,
                      'font': {'size': 9, 'face': 'monospace'}})

    root = f'd:{domain}'
    node(root, domain, 'domain')
    for host in [h for h in data['hosts'] if h['alive']][:max_hosts]:
        hid = f's:{host["name"]}'
        group = 'takeover' if host['name'] in takeover_hosts else 'subdomain'
        node(hid, host['name'][: -len(domain) - 1] or host['name'], group)
        edge(root, hid, ' ', '#00ccff')
        for c in host['cname'][:1]:
            node(f'c:{c}', c, 'cname')
            edge(hid, f'c:{c}', 'CNAME', '#888888', True)
        for ip in host['a'][:3]:
            node(f'ip:{ip}', ip, 'ip')
            edge(hid, f'ip:{ip}', 'A', '#ff8800')
    for mx in data.get('mx_records', []):
        node(f'mx:{mx["host"]}', mx['host'], 'mx')
        edge(root, f'mx:{mx["host"]}', f'MX {mx["priority"]}', '#ff4444', True)
    for ns in data.get('ns_records', []):
        node(f'ns:{ns}', ns, 'ns')
        edge(root, f'ns:{ns}', 'NS', '#aa66ff', True)
    return {'nodes': nodes, 'edges': edges}
