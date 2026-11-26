"""One-shot domain recon pipeline (runs as a background job).

domain → RDAP/WHOIS → DNS security → subdomains (multi-source + wildcard)
→ takeover check → HTTP probe → screenshots → TLS scan → port scan
→ Wayback / urlscan / favicon. Each stage is isolated: a failing stage is
recorded and the pipeline continues.
"""

import time

from tools import (
    archive_tool,
    dns_security,
    domain_tool,
    http_probe,
    portscan_tool,
    subdomain_tool,
    takeover_tool,
    tls_scan,
)

DEFAULT_OPTIONS = {
    'ports': True,
    'screenshots': True,
    'max_probe': 100,
    'max_screenshots': 12,
    'archive': True,
}

# (key, label, start %, end %)
STAGES = [
    ('whois', 'RDAP / WHOIS', 0, 4),
    ('dns_security', 'DNS security', 4, 8),
    ('subdomains', 'Subdomain enumeration', 8, 45),
    ('takeover', 'Subdomain takeover', 45, 50),
    ('http', 'HTTP probe', 50, 70),
    ('screenshots', 'Screenshot', 70, 80),
    ('tls', 'TLS scan + CT', 80, 85),
    ('ports', 'Port scan', 85, 93),
    ('archive', 'Wayback / urlscan / favicon', 93, 99),
]


class Pipeline:
    def __init__(self, ctx, domain, options):
        self.ctx = ctx
        self.domain = subdomain_tool.clean_domain(domain)
        self.options = {**DEFAULT_OPTIONS, **(options or {})}
        self.report = {'domain': self.domain, 'options': self.options, 'stages': {}}

    def _stage(self, key, func):
        label, start, end = next((lbl, s, e) for k, lbl, s, e in STAGES if k == key)
        self.ctx.progress(start, f'▶ {label}')
        started = time.monotonic()

        def sub_progress(pct, message=None):
            self.ctx.progress(start + (end - start) * pct / 100, message)

        try:
            value = func(sub_progress)
            status, error = 'ok', None
        except Exception as e:
            value, status, error = None, 'error', str(e)[:300] or type(e).__name__
            self.ctx.log(f'✖ {label}: {error}')
        self.report[key] = value
        self.report['stages'][key] = {
            'label': label, 'status': status, 'error': error,
            'seconds': round(time.monotonic() - started, 1),
        }
        self.ctx.partial('stages', self.report['stages'])
        return value

    def skip(self, key, reason):
        label = next(lbl for k, lbl, _, _ in STAGES if k == key)
        self.report[key] = None
        self.report['stages'][key] = {'label': label, 'status': 'skipped', 'error': reason, 'seconds': 0}

    def run(self):
        d = self.domain
        self._stage('whois', lambda p: domain_tool.lookup(d))
        self._stage('dns_security', lambda p: dns_security.analyse(d))
        subs = self._stage('subdomains', lambda p: subdomain_tool.enumerate_subdomains(
            d, progress=lambda pct, msg: p(pct, msg)))

        hosts = (subs or {}).get('hosts', [])
        if subs:
            self.ctx.partial('subdomains', {'total': subs['total'], 'alive': subs['alive']})
            self._stage('takeover', lambda p: takeover_tool.scan(
                hosts, progress=lambda i, n: p(100 * i / n)))
        else:
            self.skip('takeover', 'Tidak ada data subdomain')

        targets = [d] + [h['name'] for h in hosts if h['alive'] and not h.get('wildcard')]
        targets = list(dict.fromkeys(targets))[: self.options['max_probe']]
        probes = self._stage('http', lambda p: http_probe.probe_many(
            targets, progress=lambda i, n: p(100 * i / n, f'HTTP probe {i}/{n}') if i % 10 == 0 else p(100 * i / n)))
        alive = [x for x in (probes or []) if x.get('alive')]
        self.ctx.partial('http', {'alive': len(alive), 'probed': len(targets)})

        if self.options['screenshots'] and http_probe.screenshot_backend() and alive:
            def shots(p):
                out = {}
                chosen = alive[: self.options['max_screenshots']]
                for i, item in enumerate(chosen, 1):
                    name = http_probe.screenshot(item['final_url'])
                    if name:
                        out[item['host']] = name
                    p(100 * i / len(chosen), f'Screenshot {i}/{len(chosen)}')
                return out
            self._stage('screenshots', shots)
        else:
            self.skip('screenshots', 'Dinonaktifkan atau Chromium/Playwright tidak tersedia'
                      if alive else 'Tidak ada host HTTP yang hidup')

        self._stage('tls', lambda p: tls_scan.scan(d))

        if self.options['ports']:
            self._stage('ports', lambda p: portscan_tool.scan(d, 'top'))
        else:
            self.skip('ports', 'Dinonaktifkan')

        if self.options['archive']:
            self._stage('archive', lambda p: archive_tool.investigate(d))
        else:
            self.skip('archive', 'Dinonaktifkan')

        self.report['summary'] = summarise(self.report)
        return self.report


def summarise(report):
    subs = report.get('subdomains') or {}
    http = report.get('http') or []
    takeover = (report.get('takeover') or {}).get('findings', [])
    ports = report.get('ports') or {}
    tls = report.get('tls') or {}
    dnssec = report.get('dns_security') or {}
    archive = report.get('archive') or {}
    findings = []
    for t in takeover:
        findings.append({'severity': 'critical' if t['status'] == 'vulnerable' else 'high',
                         'title': f'Potensi takeover: {t["host"]} → {t["service"]}',
                         'detail': '; '.join(t['evidence'])})
    for p in ports.get('open', []):
        if p['risk'] in ('critical', 'high', 'medium'):
            findings.append({'severity': p['risk'], 'title': f'Port {p["port"]}/{p["service"]} terbuka',
                             'detail': p['risk_reason']})
    for note in tls.get('notes', []):
        findings.append({'severity': 'medium', 'title': 'TLS', 'detail': note})
    if dnssec.get('grade') in ('D', 'F'):
        findings.append({'severity': 'medium', 'title': f'DNS security grade {dnssec["grade"]}',
                         'detail': '; '.join(dnssec.get('recommendations', [])[:3])})
    wb = archive.get('wayback') or {}
    if wb.get('interesting'):
        findings.append({'severity': 'low', 'title': f'{len(wb["interesting"])} URL arsip menarik',
                         'detail': 'File konfigurasi/backup/admin pernah terindeks di Wayback'})
    order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    findings.sort(key=lambda f: order.get(f['severity'], 9))
    return {
        'subdomains': subs.get('total', 0),
        'alive_dns': subs.get('alive', 0),
        'alive_http': sum(1 for h in http if h.get('alive')),
        'takeover': len(takeover),
        'open_ports': len(ports.get('open', [])),
        'tls_grade': tls.get('grade'),
        'dns_grade': dnssec.get('grade'),
        'findings': findings,
    }


def run(ctx, domain, options=None):
    return Pipeline(ctx, domain, options).run()
