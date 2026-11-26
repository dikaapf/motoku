"""One-shot domain recon pipeline (runs as a background job).

domain → RDAP/WHOIS → DNS security → subdomains (multi-source + wildcard)
→ takeover check → HTTP probe → screenshots → TLS scan → port scan
→ Wayback / urlscan / favicon. Each stage is isolated: a failing stage is
recorded and the pipeline continues.
"""

import time

from tools import (
    archive_tool,
    cloud_tool,
    cve_tool,
    dns_security,
    domain_tool,
    http_probe,
    portscan_tool,
    subdomain_tool,
    takeover_tool,
    threat_intel,
    tls_scan,
    typosquat,
)

DEFAULT_OPTIONS = {
    'ports': True,
    'screenshots': True,
    'max_probe': 100,
    'max_screenshots': 12,
    'archive': True,
    'intel': True,
    'typosquat': True,
    'cloud': True,
}

# (key, label, start %, end %)
STAGES = [
    ('whois', 'RDAP / WHOIS', 0, 3),
    ('dns_security', 'DNS security', 3, 6),
    ('subdomains', 'Subdomain enumeration', 6, 35),
    ('takeover', 'Subdomain takeover', 35, 39),
    ('http', 'HTTP probe', 39, 52),
    ('screenshots', 'Screenshot', 52, 60),
    ('tls', 'TLS scan + CT', 60, 64),
    ('ports', 'Port scan', 64, 70),
    ('archive', 'Wayback / urlscan / favicon', 70, 74),
    ('threat_intel', 'Threat intel (reputasi domain & IP)', 74, 78),
    ('cve', 'CVE mapping + EPSS + KEV', 78, 84),
    ('typosquat', 'Typosquatting', 84, 94),
    ('cloud', 'Cloud storage', 94, 99),
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

    def _main_ips(self):
        ips = []
        whois = self.report.get('whois') or {}
        if whois.get('ip') and whois['ip'][0].isdigit():
            ips.append(whois['ip'])
        ports = self.report.get('ports') or {}
        if ports.get('ip'):
            ips.append(ports['ip'])
        return list(dict.fromkeys(ips))[:2]

    def _intel(self):
        indicators = [self.domain] + self._main_ips()
        lookups = []
        for ind in indicators:
            try:
                lookups.append(threat_intel.lookup(ind, include_unconfigured=False))
            except ValueError:
                continue
        return {'lookups': lookups}

    def _cves(self):
        services = list((self.report.get('ports') or {}).get('open', []))
        mapped = cve_tool.map_services(services, per_cpe=40) if services else \
            {'cpes': [], 'cves': [], 'summary': cve_tool.summarise([])}
        # CVEs reported by Shodan InternetDB/Shodan for the main IPs.
        known = {c['id'] for c in mapped['cves']}
        extra_ids = []
        for lk in (self.report.get('threat_intel') or {}).get('lookups', []):
            extra_ids.extend(c for c in lk.get('cves', []) if c not in known)
        if extra_ids:
            extra = cve_tool.enrich(extra_ids, details=True, max_details=40)
            for item in extra:
                item['cpes'] = ['shodan-internetdb']
            mapped['cves'].extend(extra)
            mapped['cves'].sort(key=cve_tool.sort_key)
        mapped['summary'] = cve_tool.summarise(mapped['cves'])
        return mapped

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

        # ── S3 enrichment ──
        if self.options['intel']:
            self._stage('threat_intel', lambda p: self._intel())
            self._stage('cve', lambda p: self._cves())
        else:
            self.skip('threat_intel', 'Dinonaktifkan')
            self.skip('cve', 'Dinonaktifkan')

        if self.options['typosquat']:
            self._stage('typosquat', lambda p: typosquat.scan(
                d, max_candidates=600, progress=lambda pct, msg: p(pct, msg)))
        else:
            self.skip('typosquat', 'Dinonaktifkan')

        if self.options['cloud']:
            self._stage('cloud', lambda p: cloud_tool.find_buckets(
                d, limit=40, workers=40, progress=lambda pct, msg: p(pct, msg)))
        else:
            self.skip('cloud', 'Dinonaktifkan')

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
        if p.get('risk') in ('critical', 'high', 'medium'):
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
    # ── S3 enrichment findings ──
    for lk in (report.get('threat_intel') or {}).get('lookups', []):
        verdict = lk['summary']['verdict']
        if verdict in ('malicious', 'suspicious'):
            flagged = [r['source'] for r in lk['results'] if r['verdict'] == verdict]
            findings.append({'severity': 'high' if verdict == 'malicious' else 'medium',
                             'title': f'{lk["indicator"]} ditandai {verdict}',
                             'detail': 'Sumber: ' + ', '.join(flagged)})
    cve = report.get('cve') or {}
    cs = cve.get('summary') or {}
    if cs.get('kev'):
        kev_ids = [c['id'] for c in cve.get('cves', []) if c.get('kev')][:5]
        findings.append({'severity': 'critical', 'title': f'{cs["kev"]} CVE di katalog CISA KEV',
                         'detail': 'Dieksploitasi aktif: ' + ', '.join(kev_ids)})
    if cs.get('p1'):
        findings.append({'severity': 'high', 'title': f'{cs["p1"]} CVE prioritas P1',
                         'detail': f'EPSS tertinggi {cs.get("max_epss", 0):.0%}; total {cs.get("total", 0)} CVE'})
    typo = report.get('typosquat') or {}
    high_typo = [t['domain'] for t in typo.get('registered', []) if t['risk'] == 'high']
    if high_typo:
        findings.append({'severity': 'medium', 'title': f'{len(high_typo)} domain typosquat berisiko tinggi',
                         'detail': ', '.join(high_typo[:6]) + (' …' if len(high_typo) > 6 else '')})
    cloud = report.get('cloud') or {}
    public = [b for b in cloud.get('buckets', []) if b['status'] == 'public']
    if public:
        findings.append({'severity': 'high', 'title': f'{len(public)} bucket cloud dapat di-list publik',
                         'detail': ', '.join(f'{b["provider"]}: {b["name"]}' for b in public[:5])
                         + ' (nama bucket global — kepemilikan belum diverifikasi)'})

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
        'cves': cs.get('total', 0),
        'kev': cs.get('kev', 0),
        'typosquats': typo.get('registered_count', 0),
        'public_buckets': len(public),
        'intel_verdict': _worst_verdict(report),
        'findings': findings,
    }


def run(ctx, domain, options=None):
    return Pipeline(ctx, domain, options).run()


def _worst_verdict(report):
    order = ['malicious', 'suspicious', 'clean', 'unknown']
    verdicts = [lk['summary']['verdict'] for lk in (report.get('threat_intel') or {}).get('lookups', [])]
    for v in order:
        if v in verdicts:
            return v
    return None
