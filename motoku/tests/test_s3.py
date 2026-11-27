"""Tests for S3 threat intel & enrichment. All network access is faked."""

import pytest

# ── helpers ──


class FakeResp:
    def __init__(self, payload=None, status=200, headers=None, text=None):
        self._payload = payload
        self.status_code = status
        self.headers = headers or {}
        self.text = text if text is not None else ('x' if payload is not None else '')

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f'{self.status_code}')


def set_keys(monkeypatch, **keys):
    for k, v in keys.items():
        monkeypatch.setenv(k, v)


# ── 3.1–3.3 threat intel ──

@pytest.mark.parametrize('value, kind', [
    ('8.8.8.8', 'ip'), ('2001:db8::1', 'ip'), ('Example.COM', 'domain'),
    ('https://evil.test/x', 'url'), ('44d88612fea8a8f36de82e1278abb02f', 'hash'),
    ('a' * 64, 'hash'),
])
def test_classify_indicator(value, kind):
    from tools import threat_intel

    assert threat_intel.classify(value)[0] == kind


def test_classify_rejects_garbage():
    from tools import threat_intel

    with pytest.raises(ValueError):
        threat_intel.classify('not an indicator!')


def test_lookup_reports_missing_keys_and_aggregates(monkeypatch):
    from tools import threat_intel

    for name in list(threat_intel.SOURCES):
        monkeypatch.delenv(threat_intel.SOURCES[name]['provider'].key_env or 'X_NONE', raising=False)

    def fake_get(url, **kw):
        if 'internetdb' in url:
            return FakeResp({'ip': '1.2.3.4', 'ports': [22, 80], 'vulns': ['CVE-2021-44228'], 'tags': ['c2'],
                             'cpes': [], 'hostnames': []})
        if 'greynoise' in url:
            return FakeResp({'ip': '1.2.3.4', 'noise': True, 'classification': 'malicious', 'name': 'Mirai'})
        if 'ipinfo' in url:
            return FakeResp({'ip': '1.2.3.4', 'org': 'AS1 Test', 'country': 'ID'})
        if 'stat.ripe.net' in url:
            return FakeResp({'data': {'resource': '1.2.3.0/24', 'asns': [{'asn': 1, 'holder': 'TEST'}]}})
        if 'otx' in url:
            return FakeResp({'pulse_info': {'count': 5, 'pulses': []}, 'validation': []})
        return FakeResp(None, 404)

    monkeypatch.setattr(threat_intel.requests, 'get', fake_get)
    report = threat_intel.lookup('1.2.3.4')
    by = {r['source']: r for r in report['results']}
    assert by['virustotal']['status'] == 'no_key'
    assert by['abuseipdb']['status'] == 'no_key'
    assert by['greynoise']['verdict'] == 'malicious'
    assert by['internetdb']['verdict'] == 'suspicious'
    assert report['summary']['verdict'] == 'malicious'
    assert report['cves'] == ['CVE-2021-44228']
    # malicious/ok results sort before no_key ones
    assert report['results'][0]['status'] == 'ok'


def test_virustotal_verdict(monkeypatch):
    from tools import threat_intel

    set_keys(monkeypatch, MOTOKU_VT_API_KEY='k')
    monkeypatch.setattr(threat_intel.requests, 'get', lambda url, **kw: FakeResp({'data': {'attributes': {
        'last_analysis_stats': {'malicious': 7, 'suspicious': 1, 'harmless': 60, 'undetected': 10}}}}))
    r = threat_intel.virustotal('domain', 'evil.test')
    assert r['verdict'] == 'malicious'
    assert r['summary'].startswith('7/78')


def test_abuseipdb_records_remote_quota(monkeypatch):
    from services.providers import registry as R
    from tools import threat_intel

    set_keys(monkeypatch, MOTOKU_ABUSEIPDB_API_KEY='k')
    monkeypatch.setattr(threat_intel.requests, 'get', lambda url, **kw: FakeResp(
        {'data': {'abuseConfidenceScore': 90, 'totalReports': 40}},
        headers={'X-RateLimit-Remaining': '995', 'X-RateLimit-Limit': '1000'}))
    r = threat_intel.abuseipdb('ip', '1.2.3.4')
    assert r['verdict'] == 'malicious'
    assert R.ABUSEIPDB.remote_quota()['remaining'] == 995


def test_phishtank_verified_not_phish_is_clean(monkeypatch):
    from tools import threat_intel

    monkeypatch.setattr(threat_intel.requests, 'post', lambda url, **kw: FakeResp(
        {'results': {'in_database': True, 'verified': True, 'valid': False}}))
    assert threat_intel.phishtank('url', 'https://example.com/')['verdict'] == 'clean'


def test_otx_whitelisted_with_pulses_is_not_clean(monkeypatch):
    from tools import threat_intel

    monkeypatch.setattr(threat_intel.requests, 'get', lambda url, **kw: FakeResp(
        {'pulse_info': {'count': 50, 'pulses': []}, 'validation': [{'name': 'Whitelisted'}]}))
    assert threat_intel.otx('hash', 'a' * 32)['verdict'] == 'unknown'


def test_urlhaus_host(monkeypatch):
    from tools import threat_intel

    set_keys(monkeypatch, MOTOKU_ABUSECH_API_KEY='k')
    monkeypatch.setattr(threat_intel.requests, 'post', lambda url, **kw: FakeResp({
        'query_status': 'ok', 'url_count': 2,
        'urls': [{'url': 'http://evil.test/a', 'url_status': 'online', 'threat': 'malware_download'},
                 {'url': 'http://evil.test/b', 'url_status': 'offline'}]}))
    r = threat_intel.urlhaus('domain', 'evil.test')
    assert r['verdict'] == 'malicious'
    assert '1 online' in r['summary']


def test_source_error_is_isolated(monkeypatch):
    from tools import threat_intel

    def boom(url, **kw):
        raise ConnectionError('network down')

    monkeypatch.setattr(threat_intel.requests, 'get', boom)
    r = threat_intel._run_source('ipinfo', 'ip', '1.2.3.4')
    assert r['status'] == 'error'
    assert 'network down' in r['summary']


def test_intel_route(client, monkeypatch):
    from tools import threat_intel

    monkeypatch.setattr(threat_intel, 'lookup', lambda ind: {
        'indicator': ind, 'kind': 'ip', 'cves': ['CVE-2021-44228'],
        'summary': {'verdict': 'malicious', 'malicious': 1, 'suspicious': 0, 'clean': 0, 'sources_ok': 1,
                    'sources_no_key': 3, 'sources_error': 0},
        'results': [{'source': 'greynoise', 'category': 'Reputasi', 'status': 'ok', 'verdict': 'malicious',
                     'summary': 'Mirai scanner', 'data': {'x': 1}, 'link': None}]})
    body = client.post('/intel', data={'indicator': '1.2.3.4'}).data
    assert b'Mirai scanner' in body
    assert b'Berbahaya' in body
    assert b'CVE-2021-44228' in body


# ── 3.4 CVE / EPSS / KEV ──

def test_cpe_conversion_and_version_fallback():
    from tools import cve_tool

    assert cve_tool.cpe22_to_23('cpe:/a:openbsd:openssh:6.6.1p1') == 'cpe:2.3:a:openbsd:openssh:6.6.1p1'
    assert list(cve_tool.version_candidates('cpe:2.3:a:openbsd:openssh:6.6.1p1')) == [
        'cpe:2.3:a:openbsd:openssh:6.6.1p1', 'cpe:2.3:a:openbsd:openssh:6.6.1', 'cpe:2.3:a:openbsd:openssh:6.6']
    assert list(cve_tool.version_candidates('cpe:2.3:o:canonical:ubuntu_linux')) == [
        'cpe:2.3:o:canonical:ubuntu_linux']


@pytest.mark.parametrize('item, expected', [
    ({'kev': True, 'cvss': 5.0, 'epss': 0.001}, 'P1'),
    ({'cvss': 9.8, 'epss': 0.6}, 'P1'),
    ({'cvss': 9.8, 'epss': 0.05}, 'P2'),
    ({'cvss': 7.5, 'epss': 0.001}, 'P3'),
    ({'cvss': 5.0, 'epss': 0.001}, 'P4'),
])
def test_priority(item, expected):
    from tools import cve_tool

    assert cve_tool.priority(item) == expected


def test_map_services_with_fallback_and_kev(monkeypatch):
    from tools import cve_tool

    calls = []

    def fake_get(url, params=None, **kw):
        if 'cvedb.shodan.io/cves' in url:
            calls.append(params['cpe23'])
            if params['cpe23'].endswith('6.6'):
                return FakeResp({'cves': [
                    {'cve_id': 'CVE-2016-0777', 'cvss': 6.5, 'epss': 0.2, 'kev': False, 'summary': 'roaming'},
                    {'cve_id': 'CVE-2018-15473', 'cvss': 5.3, 'epss': 0.9, 'kev': False, 'summary': 'enum'}]})
            return FakeResp({'detail': 'No CVEs'}, 404)
        if 'known_exploited' in url:
            return FakeResp({'catalogVersion': '1', 'count': 1, 'vulnerabilities': [
                {'cveID': 'CVE-2016-0777', 'vendorProject': 'OpenBSD', 'product': 'OpenSSH',
                 'vulnerabilityName': 'test', 'dateAdded': '2024-01-01', 'dueDate': '2024-02-01'}]})
        raise AssertionError(url)

    monkeypatch.setattr('services.http.requests.get', fake_get)
    result = cve_tool.map_services([{'cpe': ['cpe:/a:openbsd:openssh:6.6.1p1']}, {'cpe': []}])
    assert calls == ['cpe:2.3:a:openbsd:openssh:6.6.1p1', 'cpe:2.3:a:openbsd:openssh:6.6.1',
                     'cpe:2.3:a:openbsd:openssh:6.6']
    assert result['cpes'][0]['matched'] == 'cpe:2.3:a:openbsd:openssh:6.6'
    assert [c['id'] for c in result['cves']] == ['CVE-2016-0777', 'CVE-2018-15473']
    assert result['cves'][0]['kev'] is True
    assert result['summary'] == {'total': 2, 'kev': 1, 'critical': 0, 'high': 0, 'p1': 2, 'max_epss': 0.9}


def test_enrich_merges_epss_and_kev(monkeypatch):
    from tools import cve_tool

    def fake_get(url, params=None, **kw):
        if 'cvedb.shodan.io/cve/' in url:
            return FakeResp({'cve_id': url.rsplit('/', 1)[1], 'cvss': 9.8, 'summary': 'x', 'kev': False})
        if 'api.first.org' in url:
            return FakeResp({'data': [{'cve': 'CVE-2020-0001', 'epss': '0.75', 'percentile': '0.99'}]})
        if 'known_exploited' in url:
            return FakeResp({'vulnerabilities': [{'cveID': 'CVE-2020-0002'}]})
        raise AssertionError(url)

    monkeypatch.setattr('services.http.requests.get', fake_get)
    items = {i['id']: i for i in cve_tool.enrich(['cve-2020-0001', 'CVE-2020-0002', 'bogus'])}
    assert set(items) == {'CVE-2020-0001', 'CVE-2020-0002'}
    assert items['CVE-2020-0001']['epss'] == 0.75
    assert items['CVE-2020-0001']['priority'] == 'P1'
    assert items['CVE-2020-0002']['kev'] is True


def test_cve_route(client, monkeypatch):
    from tools import cve_tool

    monkeypatch.setattr(cve_tool, 'search', lambda q: {'mode': 'cve', 'query': q, 'cve': {
        'id': 'CVE-2021-44228', 'summary': 'Log4Shell', 'cvss': 10.0, 'cvss_version': 3.0, 'epss': 0.99,
        'epss_percentile': 1.0, 'kev': True, 'kev_info': {'name': 'Log4j RCE', 'added': '2021-12-10',
                                                           'due': '2021-12-24', 'ransomware': 'Known',
                                                           'action': 'Patch'},
        'severity': 'critical', 'priority': 'P1', 'source': 'cvedb', 'published': '2021-12-10'}})
    body = client.post('/cve', data={'query': 'CVE-2021-44228'}).data
    assert b'Log4j RCE' in body
    assert b'CISA KEV' in body
    assert client.post('/cve', data={'query': ''}).status_code == 200


def test_cve_search_validation():
    from tools import cve_tool

    with pytest.raises(ValueError):
        cve_tool.search('')
    with pytest.raises(ValueError):
        cve_tool.search('justoneword')


# ── 3.5 typosquatting & homograph ──

def test_permutations_cover_fuzzers():
    from tools import typosquat

    perms = typosquat.permutations('paypal.com')
    fuzzers = set(perms.values())
    assert {'omission', 'transposition', 'replacement', 'homoglyph', 'bitsquatting', 'tld-swap',
            'addition', 'hyphenation', 'dictionary'} <= fuzzers
    assert 'paypal.com' not in perms
    assert perms['paypl.com'] == 'omission'
    assert perms['paypal.net'] == 'tld-swap'
    assert any(not d.isascii() for d in perms)  # IDN homoglyphs are generated


def test_split_domain_handles_second_level_suffix():
    from tools import typosquat

    assert typosquat.split_domain('https://www.tokopedia.co.id/x') == ('tokopedia', 'co.id')


def test_homograph_detection():
    from tools import typosquat

    h = typosquat.analyse_homograph('xn--pypal-4ve.com')
    assert h['is_idn'] and h['suspicious']
    assert h['skeleton'] == 'paypal.com'
    assert not typosquat.analyse_homograph('paypal.com')['suspicious']


def test_typosquat_scan_risk(monkeypatch):
    from services import resolver
    from tools import typosquat

    table = {
        ('paypal.com', 'A'): ['1.1.1.1'],
        ('paypl.com', 'A'): ['6.6.6.6'], ('paypl.com', 'MX'): ['10 mx.paypl.com.'],
        ('paypal.net', 'A'): ['1.1.1.1'],
        ('paypal-login.com', 'A'): ['7.7.7.7'],
    }
    monkeypatch.setattr(resolver, 'resolve', lambda name, rtype='A', **kw: table.get((name, rtype), []))
    result = typosquat.scan('paypal.com')
    by = {r['domain']: r for r in result['registered']}
    assert by['paypl.com']['risk'] == 'high'
    assert by['paypal.net']['risk'] == 'low' and by['paypal.net']['same_ip']
    assert by['paypal-login.com']['risk'] == 'medium'
    assert result['registered'][0]['domain'] == 'paypl.com'


def test_typosquat_route_runs_job(client, monkeypatch):
    from tools import typosquat

    monkeypatch.setattr(typosquat, 'scan', lambda d, max_candidates=1500, progress=None: {
        'domain': d, 'generated': 3, 'checked': 3, 'registered_count': 1, 'fuzzers': {'omission': 3},
        'registered': [{'domain': 'exmple.com', 'ascii': 'exmple.com', 'fuzzer': 'omission', 'a': ['6.6.6.6'],
                        'ns': [], 'mx': ['mx'], 'same_ip': False, 'risk': 'high'}],
        'homograph': typosquat.analyse_homograph(d)})
    body = client.post('/typosquat', data={'domain': 'example.com', 'mode': 'scan'}, follow_redirects=True).data
    assert b'exmple.com' in body
    body = client.post('/typosquat', data={'domain': 'xn--pypal-4ve.com', 'mode': 'homograph'}).data
    assert 'mencampur skrip'.encode() in body


# ── 3.6 cloud storage & GitHub ──

def test_bucket_candidates():
    from tools import cloud_tool

    names = cloud_tool.candidates('www.acme.co.id')
    assert names[0] == 'acme.co.id'
    assert 'acme' in names and 'acme-backup' in names and 'backup-acme' in names
    assert all(cloud_tool.BUCKET_RE.match(n) for n in names)


def test_s3_states(monkeypatch):
    from tools import cloud_tool

    responses = {
        'https://s3.amazonaws.com/open': FakeResp(status=200, text='<ListBucketResult><Contents><Key>a.txt</Key></Contents></ListBucketResult>'),
        'https://s3.amazonaws.com/locked': FakeResp(status=403, text='<Error><Code>AccessDenied</Code></Error>'),
        'https://s3.amazonaws.com/none': FakeResp(status=404, text='<Code>NoSuchBucket</Code>'),
        'https://s3.amazonaws.com/moved': FakeResp(status=301, text='PermanentRedirect',
                                                   headers={'x-amz-bucket-region': 'us-west-2'}),
        'https://s3.us-west-2.amazonaws.com/moved': FakeResp(status=200, text='<ListBucketResult><Contents><Key>b</Key></Contents></ListBucketResult>'),
    }
    monkeypatch.setattr(cloud_tool.requests, 'get', lambda url, **kw: responses[url])
    assert cloud_tool.check_s3('open')['sample'] == ['a.txt']
    assert cloud_tool.check_s3('locked')['status'] == 'private'
    assert cloud_tool.check_s3('none') is None
    moved = cloud_tool.check_s3('moved')
    assert moved['status'] == 'public' and moved['region'] == 'us-west-2'


def test_secret_classification_masks_values():
    from tools import cloud_tool

    hits = cloud_tool.classify_fragment('aws_key = AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD="hunter2secret"\n'
                                        'token = process.env.TOKEN')
    types = [h['type'] for h in hits]
    assert types == ['AWS access key', 'Password assignment']
    assert all('hunter2secret' not in h['masked'] and 'IOSFODNN7EXAMP' not in h['masked'] for h in hits)
    assert 'hunter2secret' not in cloud_tool.redact('password: "hunter2secret"')


def test_github_requires_token(monkeypatch):
    from tools import cloud_tool

    monkeypatch.delenv('MOTOKU_GITHUB_TOKEN', raising=False)
    assert cloud_tool.github_leaks('example.com')['status'] == 'no_key'


def test_github_leaks(monkeypatch):
    from tools import cloud_tool

    set_keys(monkeypatch, MOTOKU_GITHUB_TOKEN='t')
    monkeypatch.setattr(cloud_tool.time, 'sleep', lambda s: None)
    item = {'repository': {'full_name': 'dev/app'}, 'path': '.env', 'html_url': 'https://github.com/dev/app/.env',
            'text_matches': [{'fragment': 'API_HOST=api.example.com\nAPI_KEY=' + 'sk_' + 'live_abcdefghijklmnopqrstuvwx'}]}
    monkeypatch.setattr(cloud_tool.requests, 'get', lambda url, **kw: FakeResp(
        {'items': [item]}, headers={'X-RateLimit-Remaining': '9', 'X-RateLimit-Limit': '10'}))
    result = cloud_tool.github_leaks('example.com', terms=['secret', 'token'])
    assert len(result['results']) == 1
    assert result['results'][0]['terms'] == ['secret', 'token']
    assert result['with_secrets'] == 1
    assert 'abcdefghijklmnop' not in str(result)


def test_cloud_route_runs_job(client, monkeypatch):
    from tools import cloud_tool

    monkeypatch.setattr(cloud_tool, 'find_buckets', lambda k, providers=(), progress=None: {
        'keyword': 'acme', 'checked': 3, 'candidates': 1, 'public': 1, 'errors': 0,
        'buckets': [{'provider': 'AWS S3', 'name': 'acme-backup', 'status': 'public', 'url': 'https://x',
                     'sample': ['db.sql']}]})
    body = client.post('/cloud', data={'keyword': 'acme.com', 'providers': ['s3']}, follow_redirects=True).data
    assert b'acme-backup' in body
    assert b'db.sql' in body


# ── 3.7 provider dashboard ──

def test_provider_daily_history():
    import db
    from services.providers import Provider

    p = Provider('hist-test', ttl=60)
    p.fetch('a', lambda: 1)
    p.fetch('a', lambda: 1)
    history = db.provider_history(1)['hist-test']
    day = next(iter(history.values()))
    assert day == {'calls': 1, 'errors': 0, 'cache_hits': 1}


def test_providers_dashboard(client):
    body = client.get('/providers').data
    for name in (b'virustotal', b'abuseipdb', b'internetdb', b'cvedb', b'cisa-kev', b'github'):
        assert name in body
    data = client.get('/providers?format=json').get_json()
    assert len(data['days']) == 14
    assert 'Reputasi' in data['groups']


def test_providers_refresh_without_keys(client, monkeypatch):
    for k in ('MOTOKU_SHODAN_API_KEY', 'MOTOKU_VT_API_KEY', 'MOTOKU_GITHUB_TOKEN'):
        monkeypatch.delenv(k, raising=False)
    assert client.post('/providers/refresh').get_json() == {'refreshed': []}


# ── Detection & recon integration (DoD S3) ──

def test_detect_hash_and_cve():
    from services import detect

    assert detect.detect('CVE-2021-44228')[0] == 'cve'
    assert detect.detect('44d88612fea8a8f36de82e1278abb02f')[0] == 'hash'
    assert detect.routes_for('cve-2021-44228')['tools'][0]['endpoint'] == 'cve'


def test_recon_enrichment(monkeypatch):
    from services import recon
    from tools import cloud_tool, cve_tool, threat_intel, typosquat

    class Ctx:
        def progress(self, *a, **k):
            pass

        def log(self, *a):
            pass

        def partial(self, *a):
            pass

    pipeline = recon.Pipeline(Ctx(), 'example.com', {})
    pipeline.report['whois'] = {'ip': '1.2.3.4'}
    pipeline.report['ports'] = {'ip': '1.2.3.4', 'open': [{'port': 22, 'cpe': ['cpe:/a:openbsd:openssh:7.4']}]}

    monkeypatch.setattr(threat_intel, 'lookup', lambda ind, include_unconfigured=True: {
        'indicator': ind, 'kind': 'ip' if ind[0].isdigit() else 'domain',
        'summary': {'verdict': 'malicious' if ind[0].isdigit() else 'clean'},
        'results': [{'source': 'abuseipdb', 'verdict': 'malicious' if ind[0].isdigit() else 'clean',
                     'status': 'ok', 'summary': ''}],
        'cves': ['CVE-2099-0001'] if ind[0].isdigit() else []})
    monkeypatch.setattr(cve_tool, 'map_services', lambda services, per_cpe=40: {
        'cpes': [{'cpe': 'x', 'matched': 'x', 'count': 1, 'error': None}],
        'cves': [{'id': 'CVE-2018-15473', 'cvss': 5.3, 'epss': 0.9, 'kev': False, 'priority': 'P1'}],
        'summary': {}})
    monkeypatch.setattr(cve_tool, 'enrich', lambda ids, details=True, max_details=40: [
        {'id': i, 'cvss': 9.8, 'epss': 0.5, 'kev': True, 'priority': 'P1'} for i in ids])

    pipeline.report['threat_intel'] = pipeline._intel()
    pipeline.report['cve'] = pipeline._cves()
    assert [lk['indicator'] for lk in pipeline.report['threat_intel']['lookups']] == ['example.com', '1.2.3.4']
    assert {c['id'] for c in pipeline.report['cve']['cves']} == {'CVE-2018-15473', 'CVE-2099-0001'}
    assert pipeline.report['cve']['summary']['kev'] == 1

    pipeline.report['typosquat'] = {'registered_count': 1, 'registered': [{'domain': 'exmple.com', 'risk': 'high'}]}
    pipeline.report['cloud'] = {'buckets': [{'provider': 'AWS S3', 'name': 'example-backup', 'status': 'public'}]}
    summary = recon.summarise(pipeline.report)
    titles = [f['title'] for f in summary['findings']]
    assert summary['findings'][0]['severity'] == 'critical'  # KEV
    assert '1.2.3.4 ditandai malicious' in titles
    assert any('bucket cloud' in t for t in titles)
    assert any('typosquat' in t for t in titles)
    assert summary['intel_verdict'] == 'malicious'
    assert summary['kev'] == 1 and summary['public_buckets'] == 1
    # silence unused-import linters for modules patched indirectly
    assert typosquat and cloud_tool


@pytest.mark.parametrize('path', ['/intel', '/cve', '/typosquat', '/cloud', '/providers'])
def test_s3_pages_render(client, path):
    assert client.get(path).status_code == 200


def test_short_brand_names_downgrade_risk(monkeypatch):
    from services import resolver
    from tools import typosquat

    table = {('nmap.org', 'A'): ['1.1.1.1'], ('nmar.org', 'A'): ['6.6.6.6'], ('nmar.org', 'MX'): ['10 mx.']}
    monkeypatch.setattr(resolver, 'resolve', lambda name, rtype='A', **kw: table.get((name, rtype), []))
    result = typosquat.scan('nmap.org')
    assert result['short_name'] is True
    assert {r['domain']: r['risk'] for r in result['registered']}['nmar.org'] == 'low'
