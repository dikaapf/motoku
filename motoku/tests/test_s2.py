"""Tests for S2 infra recon. All network access is faked."""

import json

import pytest

from app import app as flask_app

# ── 2.1 Job queue + SSE ──


def test_job_lifecycle_inline():
    from services import jobs

    @jobs.handler('unit-ok', 'Unit OK')
    def ok(ctx, value):
        ctx.progress(50, 'halfway')
        ctx.partial('seen', value)
        return {'double': value * 2}

    job_id = jobs.enqueue('unit-ok', 'x', {'value': 21})
    job = jobs.get(job_id)
    assert job['status'] == 'finished'
    assert job['progress'] == 100
    assert job['result'] == {'double': 42}
    assert any('halfway' in line for line in job['log'])


def test_job_failure_recorded():
    from services import jobs

    @jobs.handler('unit-fail')
    def fail(ctx):
        raise RuntimeError('boom')

    job = jobs.get(jobs.enqueue('unit-fail', 'x'))
    assert job['status'] == 'failed'
    assert job['error'] == 'boom'


def test_thread_backend_runs_in_background(monkeypatch):
    import threading
    import time

    from services import jobs

    gate = threading.Event()

    @jobs.handler('unit-slow')
    def slow(ctx):
        gate.wait(5)
        return 'done'

    monkeypatch.setenv('MOTOKU_JOB_BACKEND', 'thread')
    job_id = jobs.enqueue('unit-slow', 'x')
    assert jobs.get(job_id)['status'] in ('queued', 'running')
    gate.set()
    for _ in range(50):
        if jobs.get(job_id)['status'] == 'finished':
            break
        time.sleep(0.05)
    assert jobs.get(job_id)['result'] == 'done'


def test_unknown_job_kind_rejected():
    from services import jobs

    with pytest.raises(ValueError):
        jobs.enqueue('does-not-exist', 'x')


def test_job_api_and_sse(client):
    from services import jobs

    @jobs.handler('unit-sse')
    def quick(ctx):
        ctx.progress(30, 'step')
        return [1, 2, 3]

    job_id = jobs.enqueue('unit-sse', 'target')
    data = client.get(f'/api/jobs/{job_id}?result=1').get_json()
    assert data['status'] == 'finished'
    assert data['result'] == [1, 2, 3]

    response = client.get(f'/api/jobs/{job_id}/events')
    assert response.mimetype == 'text/event-stream'
    body = response.get_data(as_text=True)
    assert 'event: done' in body
    payload = json.loads(body.split('event: done\ndata: ', 1)[1].split('\n', 1)[0])
    assert payload['status'] == 'finished'

    assert client.get('/api/jobs/nope').status_code == 404
    assert client.get('/jobs').status_code == 200


def test_running_job_shows_progress_panel(client):
    import db

    db.create_job('abc123def456', 'subdomain', 'example.com', {'domain': 'example.com'})
    db.update_job('abc123def456', status='running', progress=40, message='Resolve host')
    response = client.get('/subdomain?job=abc123def456')
    assert response.status_code == 200
    assert b'data-events-url="/api/jobs/abc123def456/events"' in response.data
    assert b'Resolve host' in response.data
    # Wrong kind for the page → 404
    assert client.get('/portscan?job=abc123def456').status_code == 404


# ── 2.2 / 2.3 Subdomains, wildcard, takeover ──

def _fake_resolver(monkeypatch, table, wildcard_ip=None):
    from services import resolver

    def fake(name, rtype='A', *, raise_nx=False):
        if (name, rtype) in table:
            return table[(name, rtype)]
        if wildcard_ip and rtype == 'A' and name.startswith('motoku-'):
            return [wildcard_ip]
        if wildcard_ip and rtype == 'A' and name.endswith('.example.com') and name.split('.')[0] in ('www', 'mail', 'api'):
            return [wildcard_ip]
        return []

    monkeypatch.setattr(resolver, 'resolve', fake)


def test_subdomain_multi_source_merge(monkeypatch):
    from tools import subdomain_tool

    monkeypatch.setitem(subdomain_tool.SOURCE_FUNCS, 'crt.sh', lambda d: {'a.example.com', 'b.example.com'})
    monkeypatch.setitem(subdomain_tool.SOURCE_FUNCS, 'certspotter', lambda d: {'b.example.com'})
    monkeypatch.setitem(subdomain_tool.SOURCE_FUNCS, 'otx', lambda d: (_ for _ in ()).throw(ValueError('429')))
    monkeypatch.setitem(subdomain_tool.SOURCE_FUNCS, 'hackertarget', lambda d: set())
    _fake_resolver(monkeypatch, {
        ('a.example.com', 'A'): ['1.1.1.1'],
        ('b.example.com', 'CNAME'): ['foo.herokuapp.com.'],
    })

    data = subdomain_tool.enumerate_subdomains('https://Example.com/', brute=False)
    hosts = {h['name']: h for h in data['hosts']}
    assert data['domain'] == 'example.com'
    assert hosts['b.example.com']['sources'] == ['certspotter', 'crt.sh']
    assert hosts['b.example.com']['cname'] == ['foo.herokuapp.com']
    assert data['sources']['otx']['error'] == '429'
    assert data['wildcard']['enabled'] is False


def test_wildcard_filters_bruteforce(monkeypatch):
    from tools import subdomain_tool

    for name in list(subdomain_tool.SOURCE_FUNCS):
        monkeypatch.setitem(subdomain_tool.SOURCE_FUNCS, name, lambda d: set())
    _fake_resolver(monkeypatch, {('dev.example.com', 'A'): ['10.0.0.5']}, wildcard_ip='9.9.9.9')

    data = subdomain_tool.enumerate_subdomains('example.com')
    names = {h['name'] for h in data['hosts']}
    assert data['wildcard'] == {'enabled': True, 'ips': ['9.9.9.9']}
    assert 'dev.example.com' in names
    assert 'www.example.com' not in names


def test_source_filter_rejects_out_of_scope():
    from tools import subdomain_tool

    names = subdomain_tool._filter(['*.a.example.com', 'example.com', 'evil.com',
                                    'x.notexample.com', 'B.Example.com.'], 'example.com')
    assert names == {'a.example.com', 'b.example.com'}


def test_takeover_detection(monkeypatch):
    from services import resolver
    from tools import takeover_tool

    monkeypatch.setattr(resolver, 'resolve', lambda name, rtype='A', **kw: [])

    class Resp:
        text = "<h1>There isn't a GitHub Pages site here.</h1>"

    monkeypatch.setattr(takeover_tool.requests, 'get', lambda *a, **kw: Resp())
    result = takeover_tool.scan([
        {'name': 'docs.example.com', 'cname': ['example.github.io']},
        {'name': 'app.example.com', 'cname': ['old-app.herokuapp.com']},
        {'name': 'www.example.com', 'cname': ['example.com']},
    ])
    by_host = {f['host']: f for f in result['findings']}
    assert result['checked'] == 2
    assert by_host['docs.example.com']['service'] == 'GitHub Pages'
    assert by_host['docs.example.com']['status'] == 'vulnerable'
    assert by_host['app.example.com']['status'] == 'vulnerable'  # Heroku: NXDOMAIN suffices
    assert 'www.example.com' not in by_host


def test_subdomain_route_runs_job(client, monkeypatch):
    from tools import subdomain_tool, takeover_tool

    monkeypatch.setattr(subdomain_tool, 'enumerate_subdomains', lambda d, progress=None: {
        'domain': d, 'wildcard': {'enabled': False, 'ips': []},
        'sources': {'crt.sh': {'count': 1, 'error': None}}, 'total': 1, 'alive': 1,
        'hosts': [{'name': 'api.' + d, 'sources': ['crt.sh'], 'a': ['1.2.3.4'], 'aaaa': [],
                   'cname': [], 'alive': True, 'wildcard': False}],
        'mx_records': [], 'ns_records': [],
    })
    monkeypatch.setattr(takeover_tool, 'scan', lambda hosts: {'checked': 0, 'findings': []})
    response = client.post('/subdomain', data={'domain': 'example.com'}, follow_redirects=True)
    assert response.status_code == 200
    assert b'api.example.com' in response.data
    assert b'__GRAPH_DATA' in response.data


# ── 2.4 HTTP probe & favicon ──

def test_favicon_hash_matches_shodan_algorithm():
    pytest.importorskip('mmh3')
    # Known value: mmh3.hash(base64.encodebytes(b'hello'))
    import base64

    import mmh3

    from tools import http_probe
    assert http_probe.favicon_hash(b'hello') == mmh3.hash(base64.encodebytes(b'hello'))


def test_http_probe_parses_title(monkeypatch):
    from tools import http_probe

    class Raw:
        def read(self, n, decode_content=True):
            return b'<html><head><title> Hello &amp; Welcome </title></head></html>'

    class Resp:
        status_code = 200
        url = 'https://example.com/'
        headers = {'Server': 'nginx', 'Content-Type': 'text/html; charset=utf-8'}
        history = []
        encoding = 'utf-8'
        raw = Raw()

        def close(self):
            pass

    monkeypatch.setattr(http_probe.requests, 'get', lambda *a, **kw: Resp())
    result = http_probe.probe('example.com')
    assert result['alive'] is True
    assert result['title'] == 'Hello & Welcome'
    assert result['server'] == 'nginx'
    assert result['content_type'] == 'text/html'


# ── 2.5 Port scan ──

NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="6.6.1p1"><cpe>cpe:/a:openbsd:openssh:6.6.1p1</cpe></service></port>
<port protocol="tcp" portid="6379"><state state="open"/><service name="redis" product="Redis key-value store"/></port>
<port protocol="tcp" portid="81"><state state="closed"/><service name="hosts2-ns"/></port>
</ports></host></nmaprun>"""


def test_parse_nmap_xml_and_risk():
    from tools import portscan_tool

    results = portscan_tool.parse_nmap_xml(NMAP_XML)
    by_port = {r['port']: r for r in results}
    assert set(by_port) == {22, 6379}
    assert by_port[22]['product'] == 'OpenSSH 6.6.1p1'
    assert by_port[22]['risk'] == 'high'  # outdated OpenSSH bumps low → high
    assert by_port[6379]['risk'] == 'high'
    assert by_port[22]['cpe'] == ['cpe:/a:openbsd:openssh:6.6.1p1']


@pytest.mark.parametrize('spec, expected', [
    ('22,80', [22, 80]),
    ('20-22', [20, 21, 22]),
])
def test_parse_ports(spec, expected):
    from tools import portscan_tool

    assert portscan_tool.parse_ports(spec) == expected


@pytest.mark.parametrize('spec', ['0', '1-70000', '1-6000', 'abc'])
def test_parse_ports_invalid(spec):
    from tools import portscan_tool

    with pytest.raises(ValueError):
        portscan_tool.parse_ports(spec)


def test_portscan_falls_back_to_connect(monkeypatch):
    from tools import portscan_tool

    monkeypatch.setattr(portscan_tool, '_resolve', lambda h: '127.0.0.1')
    monkeypatch.setattr(portscan_tool, 'nmap_available', lambda: True)
    monkeypatch.setattr(portscan_tool, 'nmap_scan', lambda h, p: (_ for _ in ()).throw(ValueError('nope')))
    monkeypatch.setattr(portscan_tool, 'connect_scan', lambda h, p, progress=None: [
        {'port': 23, 'protocol': 'tcp', 'state': 'open', 'service': 'telnet', 'product': '',
         'extra': '', 'cpe': [], 'banner': '', 'risk': 'critical', 'risk_reason': 'x'}])
    result = portscan_tool.scan('host.test', '23')
    assert result['engine'] == 'connect'
    assert result['overall_risk'] == 'critical'
    assert result['summary']['critical'] == 1


def test_portscan_route(client, monkeypatch):
    from tools import portscan_tool

    monkeypatch.setattr(portscan_tool, 'scan', lambda t, p, e, progress=None: {
        'host': t, 'ip': '1.2.3.4', 'engine': 'nmap', 'ports_scanned': 2, 'overall_risk': 'high',
        'summary': {}, 'open': [{'port': 6379, 'protocol': 'tcp', 'service': 'redis', 'product': 'Redis 7',
                                 'extra': '', 'cpe': [], 'banner': '', 'risk': 'high', 'risk_reason': 'Redis'}],
    })
    response = client.post('/portscan', data={'target': 'host.test', 'ports': '6379'}, follow_redirects=True)
    assert b'Redis 7' in response.data
    assert client.post('/portscan', data={'target': 'h', 'ports': '0'}).status_code == 200


# ── 2.6 TLS scan + CT ──

def test_tls_grade_penalises_legacy_protocols():
    from tools import tls_scan

    report = {
        'certificate': {'verified': True, 'days_left': 90},
        'protocols': [
            {'protocol': 'TLSv1.3', 'supported': False},
            {'protocol': 'TLSv1.2', 'supported': True, 'cipher': 'ECDHE-RSA-AES128-GCM-SHA256'},
            {'protocol': 'TLSv1.1', 'supported': True},
            {'protocol': 'TLSv1.0', 'supported': True, 'cipher': 'DES-CBC3-SHA'},
        ],
    }
    score, letter, notes = tls_scan.grade(report)
    assert letter in ('D', 'F')
    assert 'TLS 1.0 masih aktif' in notes
    assert any('Cipher lemah' in n for n in notes)


def test_ct_history(monkeypatch):
    from tools import tls_scan

    class Resp:
        status_code = 200
        text = 'x'
        headers = {}

        def raise_for_status(self):
            pass

        def json(self):
            return [
                {'id': 1, 'issuer_name': "C=US, O=Let's Encrypt, CN=R3", 'common_name': 'example.com',
                 'name_value': 'example.com\nwww.example.com', 'not_before': '2024-01-01T00:00:00'},
                {'id': 2, 'issuer_name': 'C=US, O=DigiCert Inc, CN=X', 'common_name': 'example.com',
                 'name_value': 'example.com', 'not_before': '2020-01-01T00:00:00'},
                {'id': 1, 'issuer_name': "C=US, O=Let's Encrypt, CN=R3", 'common_name': 'example.com',
                 'name_value': 'example.com', 'not_before': '2024-01-01T00:00:00'},
            ]

    monkeypatch.setattr('services.http.requests.get', lambda *a, **kw: Resp())
    ct = tls_scan.ct_history('example.com')
    assert ct['total'] == 2
    assert ct['first_seen'].startswith('2020')
    assert dict(ct['issuers'])["Let's Encrypt"] == 1


# ── 2.7 Wayback / urlscan ──

def test_wayback_flags_interesting(monkeypatch):
    from tools import archive_tool

    class Resp:
        status_code = 200
        text = 'x'
        headers = {}

        def raise_for_status(self):
            pass

        def json(self):
            return [
                ['timestamp', 'original', 'statuscode', 'mimetype'],
                ['20200101000000', 'https://example.com/', '200', 'text/html'],
                ['20210101000000', 'https://example.com/.env', '200', 'text/plain'],
                ['20220101000000', 'https://example.com/backup.sql', '200', 'application/sql'],
            ]

    monkeypatch.setattr('services.http.requests.get', lambda *a, **kw: Resp())
    result = archive_tool.wayback('example.com')
    assert result['total'] == 3
    assert {u['url'] for u in result['interesting']} == {'https://example.com/.env',
                                                        'https://example.com/backup.sql'}
    assert result['first'] == '20200101000000'


def test_retry_helper_backs_off(monkeypatch):
    from services import http

    calls = []

    class Resp:
        def __init__(self, code):
            self.status_code = code
            self.headers = {'Retry-After': '0'}

    responses = [Resp(503), Resp(503), Resp(200)]
    monkeypatch.setattr(http.requests, 'get', lambda *a, **kw: calls.append(1) or responses.pop(0))
    monkeypatch.setattr(http.time, 'sleep', lambda s: None)
    assert http.get_with_retry('https://x.test').status_code == 200
    assert len(calls) == 3


# ── Recon pipeline (DoD S2) ──

def test_recon_pipeline_end_to_end(client, monkeypatch):
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

    monkeypatch.setattr(domain_tool, 'lookup', lambda d: {'source': 'RDAP', 'registrar': 'R', 'ip': '1.1.1.1',
                                                          'creation_date': '2000', 'expiration_date': '2030',
                                                          'name_servers': []})
    monkeypatch.setattr(dns_security, 'analyse', lambda d: {'grade': 'F', 'score': 20,
                                                            'recommendations': ['Tambahkan DMARC']})
    monkeypatch.setattr(subdomain_tool, 'enumerate_subdomains', lambda d, progress=None: {
        'domain': d, 'total': 2, 'alive': 2, 'wildcard': {'enabled': False, 'ips': []},
        'sources': {'crt.sh': {'count': 2, 'error': None}}, 'mx_records': [], 'ns_records': [],
        'hosts': [
            {'name': 'www.' + d, 'alive': True, 'wildcard': False, 'a': ['1.1.1.1'], 'cname': [], 'sources': ['crt.sh']},
            {'name': 'old.' + d, 'alive': True, 'wildcard': False, 'a': [], 'cname': ['x.herokuapp.com'], 'sources': ['crt.sh']},
        ]})
    monkeypatch.setattr(takeover_tool, 'scan', lambda hosts, progress=None: {'checked': 1, 'findings': [
        {'host': 'old.example.com', 'cname': 'x.herokuapp.com', 'service': 'Heroku',
         'status': 'vulnerable', 'evidence': ['NXDOMAIN']}]})
    monkeypatch.setattr(http_probe, 'probe_many', lambda hosts, progress=None: [
        {'host': h, 'alive': h.startswith('www'), 'status': 200, 'title': 'Home', 'server': 'nginx',
         'powered_by': '', 'final_url': f'https://{h}/'} for h in hosts])
    monkeypatch.setattr(http_probe, 'screenshot_backend', lambda: None)
    monkeypatch.setattr(tls_scan, 'scan', lambda d: {'grade': 'B', 'score': 75, 'notes': ['TLS 1.3 belum didukung'],
                                                     'protocols': [], 'certificate': None, 'ct': None})
    monkeypatch.setattr(portscan_tool, 'scan', lambda d, p: {'host': d, 'engine': 'nmap', 'open': [
        {'port': 3389, 'service': 'ms-wbt-server', 'product': '', 'banner': '', 'risk': 'high',
         'risk_reason': 'RDP terekspos'}]})

    def archive_boom(d):
        raise RuntimeError('archive down')

    monkeypatch.setattr(archive_tool, 'investigate', archive_boom)

    response = client.post('/recon', data={'domain': 'example.com', 'ports': '1', 'archive': '1'})
    assert response.status_code == 302
    job_id = response.headers['Location'].rstrip('/').split('/')[-1]

    from services import jobs

    job = jobs.get(job_id)
    assert job['status'] == 'finished'
    report = job['result']
    summary = report['summary']
    assert summary['subdomains'] == 2
    assert summary['alive_http'] == 1
    assert summary['takeover'] == 1
    assert summary['findings'][0]['severity'] == 'critical'
    assert report['stages']['archive']['status'] == 'error'
    assert report['stages']['screenshots']['status'] == 'skipped'

    page = client.get(f'/recon/{job_id}')
    assert page.status_code == 200
    assert b'Potensi takeover: old.example.com' in page.data
    assert b'RDP terekspos' in page.data
    assert client.get('/recon').status_code == 200
    assert client.get('/recon/doesnotexist').status_code == 404


@pytest.mark.parametrize('path', ['/recon', '/tls', '/archive', '/jobs'])
def test_s2_pages_render(client, path):
    assert client.get(path).status_code == 200


def test_tls_and_archive_routes(client, monkeypatch):
    from tools import archive_tool, tls_scan

    monkeypatch.setattr(tls_scan, 'scan', lambda h: {
        'host': h, 'port': 443, 'grade': 'A', 'score': 90, 'notes': [], 'certificate': None,
        'certificate_error': 'x', 'protocols': [{'protocol': 'TLSv1.3', 'supported': True,
                                                 'quality': 'good', 'cipher': 'TLS_AES', 'bits': 256}],
        'ct': {'total': 3, 'issuers': [['LE', 3]], 'recent': [], 'first_seen': '2020', 'last_seen': '2024'},
        'ct_error': None})
    assert b'TLS_AES' in client.post('/tls', data={'host': 'example.com'}).data

    monkeypatch.setattr(archive_tool, 'investigate', lambda d: {
        'domain': d, 'wayback': {'total': 1, 'truncated': False, 'first': '2020', 'last': '2021',
                                 'extensions': [], 'interesting': [{'url': 'https://e.com/.env', 'timestamp': '20200101',
                                                                    'status': '200', 'archive': 'https://web.archive.org/x'}]},
        'wayback_error': None, 'urlscan': None, 'urlscan_error': 'rate limit',
        'favicon': {'mmh3': -123, 'md5': 'abc', 'url': 'https://e.com/favicon.ico', 'size': 1,
                    'shodan_query': 'http.favicon.hash:-123'}, 'favicon_error': None})
    body = client.post('/archive', data={'domain': 'example.com'}).data
    assert b'https://e.com/.env' in body
    assert b'http.favicon.hash:-123' in body


def test_screenshot_route_blocks_traversal(client):
    assert client.get('/screenshots/../app.py').status_code == 404


def test_search_routes_domain_to_recon():
    from services import detect

    endpoints = [t['endpoint'] for t in detect.routes_for('example.com')['tools']]
    assert endpoints[0] == 'domain'
    assert 'recon' in endpoints and 'tls_page' in endpoints


def test_flask_config_unchanged():
    assert flask_app.config['TESTING'] is True


def test_tls_scan_without_tls_service_is_ungraded(monkeypatch):
    from tools import tls_scan

    def no_tls(host, port):
        raise ValueError('Tidak dapat membuka koneksi TLS')

    monkeypatch.setattr(tls_scan, 'tls_info', no_tls)
    report = tls_scan.scan('plain.test', include_ct=False)
    assert report['grade'] is None
    assert report['notes'] == []
    assert report['protocols'] == []


def test_rq_backend_enqueues_run_job(monkeypatch):
    from services import jobs

    captured = {}

    class FakeQueue:
        def enqueue(self, func, *args, **kwargs):
            captured['func'] = func
            captured['args'] = args
            captured['kwargs'] = kwargs

    @jobs.handler('unit-rq')
    def noop(ctx):
        return None

    monkeypatch.setenv('MOTOKU_JOB_BACKEND', 'rq')
    monkeypatch.setattr(jobs, '_rq_queue', lambda: FakeQueue())
    job_id = jobs.enqueue('unit-rq', 'x')
    assert captured['func'] == 'services.jobs.run_job'
    assert captured['args'] == (job_id,)
    assert jobs.get(job_id)['status'] == 'queued'

    # What the RQ worker would do:
    jobs.run_job(job_id)
    assert jobs.get(job_id)['status'] == 'finished'


def test_rq_backend_requires_redis_url(monkeypatch):
    from services import jobs

    monkeypatch.delenv('MOTOKU_REDIS_URL', raising=False)
    with pytest.raises(RuntimeError):
        jobs._rq_queue()
