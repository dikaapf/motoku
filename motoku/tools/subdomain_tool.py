import dns.resolver
import requests
import json
import re


COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'cdn', 'dev',
    'test', 'staging', 'vpn', 'remote', 'webmail', 'smtp', 'pop3',
    'imap', 'mysql', 'db', 'database', 'backup', 'beta', 'demo',
    'forum', 'help', 'intranet', 'portal', 'secure', 'status',
    'support', 'wiki', 'app', 'mobile', 'm', 'shop', 'store',
    'assets', 'download', 'docs', 'info', 'news', 'partner',
    'old', 'new', 'manager', 'ns1', 'ns2', 'ns3', 'ns4',
    'mx', 'mx1', 'mx2', 'gateway', 'firewall', 'proxy',
    'direct', 'redirect', 'tracking', 'analytics', 'stats',
    'chat', 'community', 'email', 'exchange', 'host', 'server',
    'web', 'cloud', 'login', 'signup', 'register', 'auth',
    'pay', 'payment', 'billing', 'invoice', 'ssl', 'cert',
    'redis', 'queue', 'monitor', 'logs', 'jenkins', 'git',
    'ci', 'image', 'img', 'static', 'media', 'video',
    'corp', 'office', 'global', 'eu', 'us', 'asia',
    'lb', 'loadbalancer', 'cluster', 'node', 'node1', 'node2',
    'ns1', 'ns2', 'dns1', 'dns2', 'mail1', 'mail2', 'smtp',
    'pop', 'owa', 'exchange', 'remote', 'vpn', 'radius',
    'dhcp', 'ntp', 'syslog', 'confluence', 'jira', 'svn',
    'gitlab', 'bitbucket', 'docker', 'k8s', 'kubernetes',
    'grafana', 'prometheus', 'kibana', 'elastic', 'logstash',
    'nexus', 'artifactory', 'sonar', 'sonarqube', 'jfrog',
    'swagger', 'docs', 'developer', 'sandbox', 'stage',
    'preprod', 'prod', 'production', 'release', 'rc',
    'nightly', 'daily', 'build', 'ci', 'cd', 'pipelines',
    'argo', 'harbor', 'registry', 'npm', 'pypi',
    'labs', 'research', 'internal', 'external', 'edge',
    'origin', 'akamai', 'cloudfront', 'fastly', 'cloudflare',
]


def clean_domain(domain):
    domain = domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0]
    domain = domain.split(':')[0]
    return domain


def crtsh_subdomains(domain):
    subdomains = set()
    try:
        resp = requests.get(
            f'https://crt.sh/?q=%25.{domain}&output=json',
            timeout=15,
            headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'}
        )
        if resp.status_code == 200 and resp.text:
            data = resp.json()
            for entry in data:
                name = entry.get('name_value', '')
                if name:
                    for n in name.split('\n'):
                        n = n.strip().lower()
                        if n.endswith('.' + domain) or n == domain:
                            if n != domain and '*' not in n:
                                subdomains.add(n)
    except Exception:
        pass
    return subdomains


def brute_subdomains(domain):
    subdomains = set()
    for sub in COMMON_SUBDOMAINS:
        fqdn = f'{sub}.{domain}'
        try:
            dns.resolver.resolve(fqdn, 'A', lifetime=2)
            subdomains.add(fqdn)
        except Exception:
            pass
    return subdomains


def resolve_ip(hostname):
    try:
        answers = dns.resolver.resolve(hostname, 'A', lifetime=3)
        return str(answers[0])
    except Exception:
        return None


def resolve_aaaa(hostname):
    try:
        answers = dns.resolver.resolve(hostname, 'AAAA', lifetime=3)
        return str(answers[0])
    except Exception:
        return None


def resolve_mx(domain):
    records = []
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=5)
        for r in answers:
            records.append({
                'host': str(r.exchange).rstrip('.'),
                'priority': r.preference,
            })
    except Exception:
        pass
    return records


def resolve_ns(domain):
    records = []
    try:
        answers = dns.resolver.resolve(domain, 'NS', lifetime=5)
        for r in answers:
            records.append(str(r).rstrip('.'))
    except Exception:
        pass
    return records


def build_graph(domain, subdomains, mx_records, ns_records):
    nodes = []
    edges = []
    seen_ids = set()

    domain_id = f'd:{domain}'
    nodes.append({
        'id': domain_id,
        'label': domain,
        'group': 'domain',
        'font': {'size': 20, 'face': 'monospace', 'color': '#00ff88'},
        'borderWidth': 3,
        'shape': 'box',
        'color': {
            'background': '#0d2810',
            'border': '#00ff88',
        },
    })
    seen_ids.add(domain_id)

    for s in subdomains:
        label = s.replace('.' + domain, '')
        node_id = f's:{s}'
        if node_id not in seen_ids:
            nodes.append({
                'id': node_id,
                'label': label,
                'group': 'subdomain',
                'font': {'face': 'monospace', 'color': '#88ddff'},
                'color': {
                    'background': '#0a1a28',
                    'border': '#00ccff',
                },
            })
            seen_ids.add(node_id)
        edges.append({
            'from': domain_id,
            'to': node_id,
            'label': ' ',
            'color': {'color': '#00ccff', 'opacity': 0.6},
            'width': 1.5,
            'font': {'size': 10, 'face': 'monospace'},
        })

        ip = resolve_ip(s)
        if ip:
            ip_id = f'ip:{ip}'
            if ip_id not in seen_ids:
                nodes.append({
                    'id': ip_id,
                    'label': ip,
                    'group': 'ip',
                    'font': {'face': 'monospace', 'color': '#ffaa44'},
                    'color': {
                        'background': '#281a0a',
                        'border': '#ff8800',
                    },
                    'shape': 'ellipse',
                })
                seen_ids.add(ip_id)
            edges.append({
                'from': node_id,
                'to': ip_id,
                'label': 'A',
                'color': {'color': '#ff8800', 'opacity': 0.5},
                'width': 1,
                'font': {'size': 9, 'face': 'monospace'},
            })

        ipv6 = resolve_aaaa(s)
        if ipv6:
            ip6_id = f'ip6:{ipv6}'
            if ip6_id not in seen_ids:
                nodes.append({
                    'id': ip6_id,
                    'label': ipv6,
                    'group': 'ip',
                    'font': {'face': 'monospace', 'color': '#ffaa44', 'size': 10},
                    'color': {
                        'background': '#281a0a',
                        'border': '#ff8800',
                    },
                    'shape': 'ellipse',
                })
                seen_ids.add(ip6_id)
            edges.append({
                'from': node_id,
                'to': ip6_id,
                'label': 'AAAA',
                'color': {'color': '#ff8800', 'opacity': 0.4},
                'width': 1,
                'font': {'size': 9, 'face': 'monospace'},
            })

    for mx in mx_records:
        mx_id = f'mx:{mx["host"]}'
        if mx_id not in seen_ids:
            nodes.append({
                'id': mx_id,
                'label': mx['host'],
                'group': 'mx',
                'font': {'face': 'monospace', 'color': '#ff6666'},
                'color': {
                    'background': '#281010',
                    'border': '#ff4444',
                },
                'shape': 'diamond',
            })
            seen_ids.add(mx_id)
        edges.append({
            'from': domain_id,
            'to': mx_id,
            'label': f'MX {mx["priority"]}',
            'color': {'color': '#ff4444', 'opacity': 0.7},
            'width': 2,
            'dashes': True,
            'font': {'size': 10, 'face': 'monospace'},
        })

    for ns in ns_records:
        ns_id = f'ns:{ns}'
        if ns_id not in seen_ids:
            nodes.append({
                'id': ns_id,
                'label': ns,
                'group': 'ns',
                'font': {'face': 'monospace', 'color': '#dd88ff'},
                'color': {
                    'background': '#1a1030',
                    'border': '#aa66ff',
                },
                'shape': 'triangle',
            })
            seen_ids.add(ns_id)
        edges.append({
            'from': domain_id,
            'to': ns_id,
            'label': 'NS',
            'color': {'color': '#aa66ff', 'opacity': 0.7},
            'width': 2,
            'dashes': True,
            'font': {'size': 10, 'face': 'monospace'},
        })

    return {'nodes': nodes, 'edges': edges}


def enumerate(domain):
    domain = clean_domain(domain)

    subdomains_crt = crtsh_subdomains(domain)
    subdomains_bf = brute_subdomains(domain)
    all_subdomains = sorted(subdomains_crt | subdomains_bf)

    mx_records = resolve_mx(domain)
    ns_records = resolve_ns(domain)

    subdomain_list = []
    for s in all_subdomains:
        entry = {'name': s}
        if s in subdomains_crt:
            entry['source'] = 'crt.sh'
        if s in subdomains_bf:
            if 'source' in entry:
                entry['source'] = 'crt.sh + brute'
            else:
                entry['source'] = 'bruteforce'
        subdomain_list.append(entry)

    graph = build_graph(domain, all_subdomains, mx_records, ns_records)

    return {
        'domain': domain,
        'total': len(all_subdomains),
        'subdomains': subdomain_list,
        'mx_records': mx_records,
        'ns_records': ns_records,
        'graph': graph,
    }
