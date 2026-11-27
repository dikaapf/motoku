"""Tests for S5 case management, reporting, watchlist, REST API and CLI."""

import io
import json
import zipfile

import pytest

from app import app as flask_app

# ── 5.1 / 5.3 case model, custody ──


def test_case_lifecycle_and_custody():
    import db
    from services import casedb

    cid = casedb.create_case('Investigasi A', 'scope', 'phishing, Brand', actor='tester')
    case = casedb.get_case(cid)
    assert case['tags'] == ['brand', 'phishing']
    eid = casedb.add_entity(cid, 'domain', 'Example.COM.', actor='tester')
    assert casedb.add_entity(cid, 'domain', 'example.com') == eid  # de-duplicated
    casedb.add_note(cid, 'catatan penting', 'tester', eid)
    casedb.create_finding(cid, 'high', 'Temuan uji', 'detail', 'tester')
    f = casedb.list_findings(cid)[0]
    casedb.set_finding_status(cid, f['id'], 'confirmed', 'tester')
    assert casedb.list_findings(cid)[0]['status'] == 'confirmed'

    v = casedb.verify_custody(cid)
    assert v['valid'] and v['count'] >= 5

    # Tampering with any past custody record breaks the chain.
    with db.connection() as conn:
        first = conn.execute('SELECT id FROM custody WHERE case_id = ? ORDER BY id LIMIT 1', (cid,)).fetchone()['id']
        conn.execute("UPDATE custody SET actor = 'mallory' WHERE id = ?", (first,))
    v = casedb.verify_custody(cid)
    assert not v['valid'] and v['broken_at'] == first


def test_attachments_are_hashed_and_access_logged(tmp_path, monkeypatch):
    from services import casedb

    monkeypatch.setattr(casedb, 'ATTACHMENT_DIR', str(tmp_path / 'att'))
    cid = casedb.create_case('Lampiran')
    aid = casedb.add_attachment(cid, '../../etc/passwd evil.txt', b'bukti', 'text/plain', 'screenshot', 'tester')
    meta, data = casedb.get_attachment(cid, aid, 'tester')
    assert data == b'bukti' and meta['intact']
    assert '/' not in meta['filename']
    assert any(e['type'] == 'hash' for e in casedb.list_entities(cid))
    actions = [c['action'] for c in casedb.custody_log(cid)]
    assert 'attachment.add' in actions and 'attachment.access' in actions

    # Corrupt the stored file → integrity flag flips.
    path = tmp_path / 'att' / cid / meta['sha256']
    path.write_bytes(b'diubah')
    meta, _ = casedb.get_attachment(cid, aid)
    assert meta['intact'] is False


def test_invalid_case_id_rejected_for_files():
    from services import casedb

    with pytest.raises(ValueError):
        casedb._safe_id('../x')


# ── importer (auto-fill) ──

RECON = {
    'domain': 'example.com',
    'whois': {'registrar': 'Registrar X', 'ip': '93.184.216.34'},
    'subdomains': {'domain': 'example.com', 'hosts': [
        {'name': 'www.example.com', 'alive': True, 'a': ['93.184.216.34'], 'cname': [], 'sources': ['crt.sh']},
        {'name': 'old.example.com', 'alive': True, 'a': [], 'cname': ['x.herokuapp.com'], 'sources': ['otx']},
        {'name': 'dead.example.com', 'alive': False, 'a': [], 'cname': [], 'sources': ['crt.sh']}],
        'mx_records': [{'host': 'mx.example.com', 'priority': 10}], 'ns_records': ['ns1.example.net'],
        'sources': {'crt.sh': {'count': 2, 'error': None}}, 'wildcard': {'enabled': False, 'ips': []},
        'total': 3, 'alive': 2},
    'stages': {},
    'takeover': {'findings': [{'host': 'old.example.com', 'cname': 'x.herokuapp.com', 'service': 'Heroku',
                               'status': 'vulnerable', 'evidence': []}]},
    'http': [{'host': 'www.example.com', 'alive': True, 'final_url': 'https://www.example.com/', 'title': 'Home',
              'status': 200, 'server': 'nginx'}],
    'ports': {'host': 'example.com', 'ip': '93.184.216.34', 'open': [
        {'port': 22, 'protocol': 'tcp', 'service': 'ssh', 'product': 'OpenSSH 7.4', 'cpe': [], 'risk': 'high',
         'risk_reason': 'versi usang'}]},
    'tls': {'certificate': {'serial': 'ABC123', 'subject': {'commonName': 'example.com'},
                            'issuer': {'organizationName': 'Lets Encrypt'}, 'not_after': '2027-01-01'}},
    'cve': {'cves': [{'id': 'CVE-2018-15473', 'cvss': 5.3, 'epss': 0.9, 'kev': False, 'priority': 'P1'},
                     {'id': 'CVE-2021-44228', 'cvss': 10, 'epss': 0.99, 'kev': True, 'priority': 'P1',
                      'summary': 'log4shell'}],
            'cpes': [], 'summary': {'total': 2, 'kev': 1, 'p1': 2}},
    'typosquat': {'registered_count': 1, 'registered': [{'domain': 'exampel.com', 'ascii': 'exampel.com', 'fuzzer': 'transposition',
                                  'risk': 'high'}]},
    'cloud': {'public': 1, 'buckets': [{'provider': 'AWS S3', 'name': 'example-backup', 'status': 'public'}]},
    'summary': {'findings': [{'severity': 'critical', 'title': 'Potensi takeover: old.example.com', 'detail': 'x'}]},
}


def test_import_recon_builds_graph():
    from services import casedb, importer

    cid = casedb.create_case('Recon import')
    stats = importer.import_result(cid, 'recon', RECON, 'tester', 'example.com')
    assert stats['entities_new'] >= 12 and stats['relations'] >= 10 and stats['findings'] >= 3
    ents = {(e['type'], e['value']) for e in casedb.list_entities(cid)}
    for expected in [('domain', 'example.com'), ('subdomain', 'www.example.com'), ('ip', '93.184.216.34'),
                     ('service', '93.184.216.34:22/tcp'), ('cve', 'CVE-2021-44228'), ('certificate', 'ABC123'),
                     ('domain', 'exampel.com'), ('bucket', 'AWS S3:example-backup'), ('url', 'https://www.example.com/')]:
        assert expected in ents, expected
    assert ('subdomain', 'dead.example.com') not in ents
    titles = [f['title'] for f in casedb.list_findings(cid)]
    assert 'CVE-2021-44228 ada di CISA KEV' in titles
    assert any('takeover' in t for t in titles)

    # Re-import is idempotent for entities and findings.
    again = importer.import_result(cid, 'recon', RECON, 'tester')
    assert again['entities_new'] == 0 and again['findings'] == 0
    assert casedb.verify_custody(cid)['valid']


@pytest.mark.parametrize('tool, data, expect', [
    ('email', {'email': 'a@example.com', 'domain': 'example.com', 'mx': [{'host': 'mx.example.com'}],
               'gravatar': None, 'hibp': {'breaches': [{'title': 'Breach', 'date': '2020', 'data_classes': ['pw']}]},
               'risk_notes': []}, ('email', 'a@example.com')),
    ('social', {'username': 'alice', 'results': [{'profiles': [
        {'platform': 'GitHub', 'username': 'alice', 'url': 'https://github.com/alice', 'name': 'Alice'}]}]},
     ('account', 'https://github.com/alice')),
    ('phone', {'e164': '+6281234567890', 'operator': 'Telkomsel'}, ('phone', '+6281234567890')),
    ('geo', {'lat': -6.1, 'lng': 106.8, 'address': {'display_name': 'Jakarta'}}, ('location', '-6.1, 106.8')),
    ('intel', {'indicator': '1.2.3.4', 'kind': 'ip', 'summary': {'verdict': 'malicious'},
               'results': [{'source': 'x', 'verdict': 'malicious', 'status': 'ok', 'data': {}}], 'cves': []},
     ('ip', '1.2.3.4')),
    ('unknown_tool', {'text': 'contact admin@corp.example.org at 8.8.8.8 about CVE-2020-1234 see https://corp.example.org/x'},
     ('cve', 'CVE-2020-1234')),
])
def test_importer_extractors(tool, data, expect):
    from services import importer

    bundle = importer.extract(tool, data)
    assert expect in {(e['type'], e['value']) for e in bundle['entities']}


def test_generic_extractor_skips_filenames_and_private_ips():
    from services import importer

    bundle = importer.extract('whatever', {'a': 'style.css 10.0.0.1 config.json real-site.com'})
    values = {e['value'] for e in bundle['entities']}
    assert 'real-site.com' in values
    assert 'style.css' not in values and '10.0.0.1' not in values


# ── routes: cases UI, save-to-case, export ──

def test_case_ui_flow(client):
    resp = client.post('/cases', data={'title': 'UI case', 'description': 'd', 'tags': 'x'})
    assert resp.status_code == 302
    cid = resp.headers['Location'].rsplit('/', 1)[1]

    r = client.post(f'/cases/{cid}/import', json={'tool': 'recon_report', 'data': RECON, 'label': 'example.com'})
    assert r.status_code == 200 and r.get_json()['entities_new'] > 10

    for tab in ('overview', 'graph', 'entities', 'findings', 'timeline'):
        assert client.get(f'/cases/{cid}?tab={tab}').status_code == 200
    graph = client.get(f'/cases/{cid}/graph.json').get_json()
    assert len(graph['nodes']) > 10 and graph['edges']
    assert client.get(f'/cases/{cid}/timeline.json').get_json()

    client.post(f'/cases/{cid}/notes', data={'body': 'catatan'})
    client.post(f'/cases/{cid}/findings', data={'severity': 'low', 'title': 'Manual'})
    client.post(f'/cases/{cid}/entities', data={'type': 'email', 'value': 'x@example.com'})
    client.post(f'/cases/{cid}/attachments', data={'file': (io.BytesIO(b'evidence'), 'e.txt')},
                content_type='multipart/form-data')
    assert b'e.txt' in client.get(f'/cases/{cid}?tab=attachments').data
    assert b'VALID' in client.get(f'/cases/{cid}/custody').data
    assert client.get('/cases.json').get_json()[0]['id'] == cid


def test_case_exports(client):
    from services import casedb, importer

    cid = casedb.create_case('Export')
    importer.import_result(cid, 'recon', RECON)
    md = client.get(f'/cases/{cid}/report.md')
    assert md.status_code == 200 and b'# Laporan Investigasi: Export' in md.data
    assert md.headers['X-Content-SHA256']
    js = client.get(f'/cases/{cid}/report.json').get_json()
    assert js['summary']['entities'] > 10 and js['custody']['valid']
    html = client.get(f'/cases/{cid}/report.html?view=1')
    assert b'Chain of custody' in html.data
    z = zipfile.ZipFile(io.BytesIO(client.get(f'/cases/{cid}/report.zip').data))
    assert {'entities.csv', 'findings.csv', 'relations.csv', 'timeline.csv', 'custody.csv'} <= set(z.namelist())
    assert 'CVE-2021-44228' in z.read('entities.csv').decode('utf-8-sig')
    assert client.get(f'/cases/{cid}/report.exe').status_code == 404
    assert [c['action'] for c in casedb.custody_log(cid)].count('report.export') == 4


def test_pdf_export_uses_chromium(client, monkeypatch):
    from services import casedb, report

    cid = casedb.create_case('PDF')
    monkeypatch.setattr(report, 'html_to_pdf', lambda html: b'%PDF-1.7 fake')
    resp = client.get(f'/cases/{cid}/report.pdf')
    assert resp.data.startswith(b'%PDF') and resp.mimetype == 'application/pdf'

    def no_chromium(html):
        raise RuntimeError('Chromium tidak ditemukan')
    monkeypatch.setattr(report, 'html_to_pdf', no_chromium)
    assert client.get(f'/cases/{cid}/report.pdf').status_code == 503


def test_case_delete_requires_confirmation(client):
    from services import casedb

    cid = casedb.create_case('Hapus')
    assert client.post(f'/cases/{cid}/delete', data={'confirm': 'salah'}).status_code == 400
    assert client.post(f'/cases/{cid}/delete', data={'confirm': cid}).status_code == 302
    assert casedb.get_case(cid) is None


def test_import_finished_job(client):
    from services import casedb, jobs

    @jobs.handler('unit-portscan-like')
    def fake(ctx):
        return {'host': 'h.example.com', 'ip': '1.2.3.4', 'open': [{'port': 6379, 'service': 'redis', 'risk': 'high',
                                                                    'risk_reason': 'Redis'}]}

    job_id = jobs.enqueue('unit-portscan-like', 'h.example.com')
    cid = casedb.create_case('Job import')
    r = client.post(f'/cases/{cid}/import', json={'job_id': job_id})
    assert r.status_code == 200
    # Unknown job kind falls back to the generic extractor.
    assert ('ip', '1.2.3.4') in {(e['type'], e['value']) for e in casedb.list_entities(cid)}


# ── 5.6 recon with case auto-import ──

def test_recon_job_imports_into_new_case(client, monkeypatch):
    from services import casedb, recon

    monkeypatch.setattr(recon, 'run', lambda ctx, domain, options=None: dict(RECON, domain=domain))
    resp = client.post('/recon', data={'domain': 'example.com', 'case_id': '__new__'})
    job_id = resp.headers['Location'].rsplit('/', 1)[1]
    from services import jobs

    job = jobs.get(job_id)
    assert job['status'] == 'finished'
    cid = job['params']['case_id']
    assert casedb.get_case(cid)['title'] == 'Recon example.com'
    assert job['result']['case_import']['entities_new'] > 10
    assert b'sudah diimpor' in client.get(f'/recon/{job_id}').data


# ── 5.5 watchlist ──

def test_watch_diff_rules():
    from services import watch

    assert watch.diff('dns', None, {'A': ['1.1.1.1']}, 't') == []  # baseline
    alerts = watch.diff('dns', {'A': ['1.1.1.1'], 'NS': ['a']}, {'A': ['2.2.2.2'], 'NS': ['a']}, 'ex.com')
    assert alerts and alerts[0][1] == 'DNS A ex.com berubah'
    assert watch.diff('ports', {'ports': [80], 'vulns': []}, {'ports': [80, 3389], 'vulns': ['CVE-1']}, 'ip')[0][0] == 'high'
    assert watch.diff('tls', {'serial': 'a', 'issuer': 'X', 'days_left': 60, 'verified': True},
                      {'serial': 'a', 'issuer': 'X', 'days_left': 7, 'verified': True}, 'd')[0][0] == 'high'
    assert watch.diff('intel', {'verdict': 'clean'}, {'verdict': 'malicious', 'flagged_by': ['vt']}, 'd')


def test_watch_run_creates_alerts_and_delivers(monkeypatch):
    from services import casedb, watch

    cid = casedb.create_case('Watch case')
    snapshots = iter([{'ports': [80], 'vulns': []}, {'ports': [80, 23], 'vulns': []}])
    monkeypatch.setitem(watch.CHECKS, 'ports', lambda target: next(snapshots))
    sent = []
    monkeypatch.setattr(watch.requests, 'post', lambda url, json=None, **kw: sent.append((url, json)) or
                        type('R', (), {'status_code': 200})())
    wid = watch.add('ip', '1.2.3.4', ['ports'], 60, cid, notify={'webhook': 'https://hooks.slack.com/services/x'})

    first = watch.run_watch(watch.get(wid))
    assert first['status'] == 'baseline' and not first['alerts']
    second = watch.run_watch(watch.get(wid))
    assert second['alerts'][0]['title'] == 'Port baru terbuka di 1.2.3.4'
    assert sent and 'text' in sent[0][1]  # Slack format
    alert = watch.list_alerts(10, cid)[0]
    assert alert['delivery']
    assert any(f['source'] == 'watchlist' for f in casedb.list_findings(cid))
    watch.acknowledge(alert['id'])
    assert watch.list_alerts(10, cid, unacked=True) == []


def test_watch_due_and_lease(monkeypatch):
    from services import watch

    wid = watch.add('domain', 'example.com', ['dns'], 60)
    assert any(w['id'] == wid for w in watch.due())
    monkeypatch.setitem(watch.CHECKS, 'dns', lambda t: {'A': ['1.1.1.1']})
    assert wid in watch.run_due()  # inline backend in tests runs immediately
    assert not any(w['id'] == wid for w in watch.due())
    assert watch.get(wid)['last_status'] == 'baseline'
    assert watch.acquire_lease('t', 30) is True
    assert watch.acquire_lease('t', 30) is True  # same owner renews


def test_watch_validation():
    from services import watch

    with pytest.raises(ValueError):
        watch.add('car', 'x')
    with pytest.raises(ValueError):
        watch.add('domain', '')


def test_watchlist_pages(client, monkeypatch):
    from services import watch

    client.post('/watchlist', data={'type': 'domain', 'target': 'example.com', 'checks': ['dns'], 'interval': '60'})
    item = watch.list_all()[0]
    assert item['checks'] == ['dns'] and item['interval_min'] == 60
    assert b'example.com' in client.get('/watchlist').data
    monkeypatch.setitem(watch.CHECKS, 'dns', lambda t: {'A': []})
    assert client.post(f'/watchlist/{item["id"]}/run').status_code == 302
    client.post(f'/watchlist/{item["id"]}/toggle')
    assert watch.get(item['id'])['enabled'] == 0


def test_email_delivery_needs_smtp(monkeypatch):
    from services import watch

    monkeypatch.delenv('MOTOKU_SMTP_HOST', raising=False)
    result = watch.deliver({'id': 1, 'type': 'domain', 'target': 'x', 'notify': {'email': 'a@b.c'}},
                           {'severity': 'high', 'title': 't', 'detail': ''})
    assert 'MOTOKU_SMTP_HOST' in result['email:a@b.c']


# ── 5.7 REST API ──

@pytest.fixture
def token():
    from services import api_tokens

    return api_tokens.create('test', ['read', 'write', 'scan'])


def auth(tok):
    return {'Authorization': f'Bearer {tok}'}


def test_api_requires_valid_token(client):
    assert client.get('/api/v1/me').status_code == 401
    assert client.get('/api/v1/me', headers=auth('mtk_wrong')).status_code == 401


def test_api_scope_enforced(client):
    from services import api_tokens

    ro = api_tokens.create('ro', ['read'])
    assert client.get('/api/v1/me', headers=auth(ro)).get_json()['scopes'] == ['read']
    assert client.post('/api/v1/cases', json={'title': 'x'}, headers=auth(ro)).status_code == 403
    assert client.post('/api/v1/tools/dns', json={'value': 'x'}, headers=auth(ro)).status_code == 403


def test_api_revoked_token(client, token):
    from services import api_tokens

    tid = api_tokens.list_tokens()[0]['id']
    api_tokens.revoke(tid)
    assert client.get('/api/v1/me', headers=auth(token)).status_code == 401


def test_api_case_flow(client, token, monkeypatch):
    from tools import dns_security

    r = client.post('/api/v1/cases', json={'title': 'API case', 'tags': ['api']}, headers=auth(token))
    assert r.status_code == 201
    cid = r.get_json()['id']
    assert client.post(f'/api/v1/cases/{cid}/entities', json={'type': 'domain', 'value': 'example.com'},
                       headers=auth(token)).status_code == 201
    client.post(f'/api/v1/cases/{cid}/notes', json={'body': 'hi'}, headers=auth(token))
    client.post(f'/api/v1/cases/{cid}/findings', json={'title': 'F', 'severity': 'low'}, headers=auth(token))

    monkeypatch.setattr(dns_security, 'analyse', lambda d: {
        'domain': d, 'grade': 'F', 'score': 10, 'recommendations': [],
        'sections': {'dmarc': {'checks': [{'status': 'fail', 'title': 'DMARC tidak ada', 'detail': '',
                                          'recommendation': 'Tambah DMARC'}]}}})
    r = client.post('/api/v1/tools/dns-security', json={'value': 'example.com', 'case_id': cid}, headers=auth(token))
    assert r.get_json()['result']['grade'] == 'F'
    assert r.get_json()['case_import']['findings'] == 1

    detail = client.get(f'/api/v1/cases/{cid}', headers=auth(token)).get_json()
    assert detail['custody']['valid']
    assert any(f['title'] == 'example.com: DMARC tidak ada' for f in detail['findings'])
    md = client.get(f'/api/v1/cases/{cid}/report?format=md', headers=auth(token))
    assert md.data.startswith(b'# Laporan')
    custody_actors = {c['actor'] for c in __import__('services.casedb', fromlist=['x']).custody_log(cid)}
    assert 'api:test' in custody_actors


def test_api_jobs_and_tools(client, token):
    assert 'dns-security' in client.get('/api/v1/tools', headers=auth(token)).get_json()
    assert client.post('/api/v1/tools/nope', json={'value': 'x'}, headers=auth(token)).status_code == 404
    assert client.post('/api/v1/tools/dns', json={}, headers=auth(token)).status_code == 400
    assert client.post('/api/v1/jobs', json={'kind': 'watch'}, headers=auth(token)).status_code == 400

    from services import jobs

    @jobs.handler('unit-api')
    def j(ctx, x):
        return {'x': x}

    r = client.post('/api/v1/jobs', json={'kind': 'unit-api', 'params': {'x': 5}}, headers=auth(token))
    assert r.status_code == 202
    job = client.get(f'/api/v1/jobs/{r.get_json()["job_id"]}', headers=auth(token)).get_json()
    assert job['status'] == 'finished' and job['result'] == {'x': 5}


def test_api_detect_and_watchlist(client, token):
    assert client.get('/api/v1/detect?q=8.8.8.8', headers=auth(token)).get_json()['type'] == 'ip'
    r = client.post('/api/v1/watchlist', json={'type': 'domain', 'target': 'Example.com'}, headers=auth(token))
    assert r.status_code == 201 and r.get_json()['target'] == 'example.com'
    assert client.get('/api/v1/alerts', headers=auth(token)).get_json() == []


def test_api_bypasses_csrf_and_basic_auth(client, token):
    flask_app.config.update(CSRF_ENABLED=True, AUTH_USER='u', AUTH_PASSWORD='p')
    try:
        assert client.get('/cases').status_code == 401  # web UI still protected
        assert client.post('/api/v1/cases', json={'title': 'x'}, headers=auth(token)).status_code == 201
    finally:
        flask_app.config.update(CSRF_ENABLED=False, AUTH_USER='', AUTH_PASSWORD='')


def test_token_settings_page(client):
    body = client.post('/settings/tokens', data={'name': 'cli', 'scopes': ['read', 'scan']}).data
    assert b'mtk_' in body
    from services import api_tokens
    t = api_tokens.list_tokens()[0]
    assert t['scopes'] == ['read', 'scan'] and t['name'] == 'cli'
    client.post(f'/settings/tokens/{t["id"]}/revoke')
    assert api_tokens.list_tokens()[0]['revoked'] == 1
    assert client.get('/api/v1/docs').status_code == 200


# ── 5.8 CLI ──

def test_cli_against_test_client(client, token, monkeypatch, capsys):
    import cli

    class Adapter:
        """Route the CLI's requests.Session through the Flask test client."""

        def __init__(self):
            self.headers = {}

        def request(self, method, url, timeout=None, params=None, json=None):
            path = url.split('://', 1)[1].split('/', 1)[1]
            resp = client.open('/' + path, method=method, query_string=params, json=json, headers=self.headers)

            class R:
                status_code = resp.status_code
                headers = {'Content-Type': resp.content_type}
                text = resp.get_data(as_text=True)

                def json(self):
                    return resp.get_json()
            return R()

    monkeypatch.setattr(cli.requests, 'Session', Adapter)
    assert cli.main(['--token', token, 'case', 'create', 'CLI case']) == 0
    cid = capsys.readouterr().out.strip()
    cli.main(['--token', token, 'case', 'add-entity', cid, 'domain', 'cli.example.com'])
    cli.main(['--token', token, 'case', 'list'])
    assert 'CLI case' in capsys.readouterr().out
    cli.main(['--token', token, 'case', 'report', cid])
    assert 'cli.example.com' in capsys.readouterr().out
    cli.main(['--token', token, 'detect', 'example.com'])
    assert 'Domain' in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli.main(['--token', 'mtk_bad', 'case', 'list'])


def test_cli_requires_token():
    import cli

    with pytest.raises(SystemExit):
        cli.main(['--token', '', 'case', 'list'])


def test_extension_manifest_is_valid():
    import os

    root = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'extension')
    manifest = json.load(open(os.path.join(root, 'manifest.json')))
    assert manifest['manifest_version'] == 3
    for f in ('background.js', 'popup.html', 'popup.js', 'options.html', 'options.js', 'common.js'):
        assert os.path.exists(os.path.join(root, f))


@pytest.mark.parametrize('path', ['/cases', '/watchlist', '/settings/tokens', '/api/v1/docs', '/api/v1'])
def test_s5_pages_render(client, path):
    assert client.get(path).status_code == 200


def test_graph_folds_low_priority_cves(client):
    from services import casedb, importer

    cid = casedb.create_case('Banyak CVE')
    cves = [{'id': f'CVE-2020-{1000 + i}', 'cvss': 5, 'epss': i / 100, 'kev': False, 'priority': 'P3'} for i in range(60)]
    importer.import_result(cid, 'recon', dict(RECON, cve={'cves': cves, 'cpes': [], 'summary': {}}))
    g = client.get(f'/cases/{cid}/graph.json?cve_limit=10').get_json()
    assert g['hidden'] >= 50
    assert any(n['id'] == 'cve-more' for n in g['nodes'])
    assert sum(1 for n in g['nodes'] if n['group'] == 'cve' and n['id'] != 'cve-more') == 10
