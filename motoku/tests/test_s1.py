"""Tests for the S1 core OSINT upgrade. All network access is faked."""

import pytest

from app import app as flask_app

# ── 1.1 Unified search / input detection ──

@pytest.mark.parametrize('query, expected', [
    ('user@example.com', 'email'),
    ('8.8.8.8', 'ip'),
    ('2001:4860:4860::8888', 'ip'),
    ('https://example.com/path', 'url'),
    ('example.co.id', 'domain'),
    ('+6281234567890', 'phone'),
    ('081234567890', 'phone'),
    ('john_doe', 'username'),
    ('@john.doe', 'username'),
    ('Budi Santoso', 'name'),
    ('', None),
])
def test_detect_types(query, expected):
    from services import detect

    assert detect.detect(query)[0] == expected


def test_routes_adapt_value_per_tool():
    from services import detect

    routing = detect.routes_for('alice@example.com')
    by_endpoint = {t['endpoint']: t['value'] for t in routing['tools']}
    assert routing['tools'][0]['endpoint'] == 'email'
    assert by_endpoint['dns_security_page'] == 'example.com'
    assert by_endpoint['username'] == 'alice'

    routing = detect.routes_for('example.com')
    by_endpoint = {t['endpoint']: t['value'] for t in routing['tools']}
    assert by_endpoint['web_security_page'] == 'https://example.com'


def test_search_page_and_redirect(client):
    response = client.get('/search?q=example.com')
    assert response.status_code == 200
    assert b'Domain' in response.data
    assert b'DNS Security' in response.data

    response = client.get('/search?q=example.com&go=1')
    assert response.status_code == 302
    assert '/domain?q=example.com' in response.headers['Location']

    assert client.get('/search').status_code == 302


def test_api_detect(client):
    data = client.get('/api/detect?q=8.8.8.8').get_json()
    assert data['type'] == 'ip'
    assert data['tools'][0]['endpoint'] == 'ip_track'


# ── 1.7 Provider abstraction, cache & quota ──

def test_provider_caches_and_counts():
    import db
    from services.providers import Provider

    provider = Provider('unit-test', ttl=60)
    calls = []

    def fetch():
        calls.append(1)
        return {'value': 42}

    assert provider.fetch('k', fetch) == {'value': 42}
    assert provider.fetch('k', fetch) == {'value': 42}
    assert len(calls) == 1

    usage = {row['provider']: row for row in db.provider_usage()}['unit-test']
    assert usage['calls'] == 1
    assert usage['cache_hits'] == 1


def test_provider_quota_enforced():
    from services.providers import Provider, QuotaExceeded

    provider = Provider('quota-test', ttl=60, daily_quota=2)
    provider.fetch('a', lambda: 1)
    provider.fetch('b', lambda: 2)
    assert provider.remaining() == 0
    with pytest.raises(QuotaExceeded):
        provider.fetch('c', lambda: 3)
    # Cached keys are still served once the quota is exhausted.
    assert provider.fetch('a', lambda: 99) == 1


def test_provider_requires_key(monkeypatch):
    from services.providers import Provider, ProviderUnavailable

    provider = Provider('key-test', key_env='MOTOKU_TEST_KEY')
    monkeypatch.delenv('MOTOKU_TEST_KEY', raising=False)
    with pytest.raises(ProviderUnavailable):
        provider.fetch('x', lambda: 1)
    monkeypatch.setenv('MOTOKU_TEST_KEY', 'secret')
    assert provider.fetch('x', lambda: 1) == 1


def test_provider_errors_not_cached():
    import db
    from services.providers import Provider

    provider = Provider('error-test')

    def boom():
        raise RuntimeError('down')

    with pytest.raises(RuntimeError):
        provider.fetch('k', boom)
    assert provider.fetch('k', lambda: 'ok') == 'ok'
    usage = {row['provider']: row for row in db.provider_usage()}['error-test']
    assert usage['errors'] == 1


def test_redis_cache_backend():
    fakeredis = pytest.importorskip('fakeredis')
    from services import cache
    from services.providers import Provider

    cache.set_backend(cache.RedisCache(fakeredis.FakeRedis()))
    provider = Provider('redis-test', daily_quota=5)
    assert provider.fetch('k', lambda: {'a': [1, 2]}) == {'a': [1, 2]}
    assert provider.fetch('k', lambda: None) == {'a': [1, 2]}
    assert provider.used_today() == 1
    assert cache.info()['backend'] == 'redis'


def test_status_page_lists_providers(client):
    response = client.get('/status')
    assert response.status_code == 200
    assert b'hibp' in response.data
    assert b'MOTOKU_HIBP_API_KEY' in response.data


# ── DNS resolver with DoH fallback ──

def test_resolver_falls_back_to_doh(monkeypatch):
    import dns.resolver

    from services import resolver

    def no_answer(*args, **kwargs):
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.resolver, 'resolve', no_answer)
    monkeypatch.setattr(resolver, 'doh_query', lambda name, rtype, dnssec=False: {
        'Status': 0,
        'Answer': [{'type': 16, 'data': '"v=spf1 include:_spf.example.com" " -all"'}],
    })
    assert resolver.resolve('example.com', 'TXT') == ['v=spf1 include:_spf.example.com -all']

    monkeypatch.setenv('MOTOKU_DNS_DOH_FALLBACK', '0')
    assert resolver.resolve('example.com', 'TXT') == []


# ── 1.2 WhatsMyName ──

SITE = {
    'name': 'Example', 'uri_check': 'https://example.com/u/{account}', 'cat': 'social',
    'e_code': 200, 'e_string': 'profile-card', 'm_code': 404, 'm_string': 'Not Found',
}


@pytest.mark.parametrize('code, body, expected', [
    (200, '<div class="profile-card">', 'found'),
    (404, 'Not Found', 'not_found'),
    (200, 'Not Found page with no profile', 'not_found'),
    (500, 'oops', 'unknown'),
    (403, 'Access denied', 'unknown'),
    (410, 'Gone', 'not_found'),
])
def test_wmn_evaluate(code, body, expected):
    from tools import wmn_tool

    assert wmn_tool.evaluate(SITE, code, body) == expected


def test_wmn_search_parallel(monkeypatch):
    from tools import wmn_tool

    sites = [dict(SITE, name=f'Site{i}', uri_check=f'https://s{i}.test/{{account}}') for i in range(5)]
    sites.append(dict(SITE, name='Adult', cat=wmn_tool.NSFW_CATEGORY))
    sites.append(dict(SITE, name='Disabled', valid=False))
    monkeypatch.setattr(wmn_tool, 'load_dataset', lambda path=None: {'sites': sites, 'categories': ['social']})

    def fake_check(site, username, timeout, session):
        found = site['name'] in ('Site1', 'Site3')
        return {'name': site['name'], 'category': site['cat'], 'url': site['uri_check'],
                'status': 'found' if found else 'not_found', 'http_code': 200, 'error': None}

    monkeypatch.setattr(wmn_tool, 'check_site', fake_check)
    result = wmn_tool.search('alice')
    assert result['checked'] == 5
    assert result['counts']['found'] == 2
    assert [r['name'] for r in result['results'][:2]] == ['Site1', 'Site3']

    with pytest.raises(ValueError):
        wmn_tool.search('bad name with spaces')


def test_bundled_wmn_dataset_loads():
    from tools import wmn_tool

    info = wmn_tool.dataset_info()
    assert info['total_sites'] > 500
    assert 'social' in info['categories']


def test_username_route(client, monkeypatch):
    from tools import wmn_tool

    monkeypatch.setattr(wmn_tool, 'search', lambda u, categories=None, include_nsfw=False, progress=None: {
        'username': u, 'checked': 1, 'elapsed_s': 0.1,
        'counts': {'found': 1, 'not_found': 0, 'unknown': 0},
        'results': [{'name': 'GitHub', 'category': 'coding', 'url': 'https://github.com/alice',
                     'status': 'found', 'http_code': 200, 'error': None}],
    })
    response = client.post('/username', data={'username': 'alice'}, follow_redirects=True)
    assert response.status_code == 200
    assert b'https://github.com/alice' in response.data
    assert b'id="result-data"' in response.data


# ── 1.3 Email intelligence ──

def test_email_classification(monkeypatch):
    from tools import email_tool

    monkeypatch.setattr(email_tool, 'mx_records', lambda d: [{'priority': 10, 'host': 'mx.' + d}])
    monkeypatch.setattr(email_tool, 'gravatar', lambda e: None)
    report = email_tool.investigate('Admin+x@Mailinator.com', use_emailrep=False)
    assert report['email'] == 'Admin+x@mailinator.com'
    assert report['disposable'] is True
    assert report['role'] is True
    assert report['plus_alias'] is True
    assert report['hibp']['status'] == 'no_key'
    assert report['risk_level'] in ('sedang', 'tinggi')

    report = email_tool.investigate('someone@gmail.com', use_emailrep=False)
    assert report['free_provider'] is True
    assert report['disposable'] is False


def test_email_invalid_syntax():
    from tools import email_tool

    with pytest.raises(ValueError):
        email_tool.investigate('not-an-email')


def test_hibp_breaches(monkeypatch):
    from tools import email_tool

    monkeypatch.setenv('MOTOKU_HIBP_API_KEY', 'k')

    class Resp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return [{'Name': 'Old', 'Title': 'Old', 'BreachDate': '2015-01-01', 'PwnCount': 5,
                     'DataClasses': ['Passwords']},
                    {'Name': 'New', 'Title': 'New', 'BreachDate': '2023-01-01', 'PwnCount': 9,
                     'DataClasses': ['Emails']}]

    captured = {}

    def fake_get(url, **kwargs):
        captured['headers'] = kwargs['headers']
        return Resp()

    monkeypatch.setattr(email_tool.requests, 'get', fake_get)
    result = email_tool.hibp('a@example.com')
    assert result['status'] == 'breached'
    assert [b['name'] for b in result['breaches']] == ['New', 'Old']
    assert captured['headers']['hibp-api-key'] == 'k'


def test_email_route(client, monkeypatch):
    from tools import email_tool

    monkeypatch.setattr(email_tool, 'mx_records', lambda d: [])
    monkeypatch.setattr(email_tool, 'gravatar', lambda e: None)
    monkeypatch.setattr(email_tool, 'emailrep', lambda e: (_ for _ in ()).throw(ValueError('rate limited')))
    response = client.post('/email', data={'email': 'x@nomx.test'})
    assert response.status_code == 200
    assert b'Tanpa MX' in response.data
    assert b'rate limited' in response.data


# ── 1.4 DNS security ──

def _fake_dns(records):
    def fake(name, rtype='A', *, raise_nx=False):
        return records.get((name, rtype), [])
    return fake


def test_dns_security_strong_domain(monkeypatch):
    from services import resolver
    from tools import dns_security

    records = {
        ('example.com', 'TXT'): ['v=spf1 include:_spf.example.net -all'],
        ('_dmarc.example.com', 'TXT'): ['v=DMARC1; p=reject; rua=mailto:d@example.com'],
        ('selector1._domainkey.example.com', 'TXT'): ['v=DKIM1; k=rsa; p=' + 'A' * 392],
        ('example.com', 'DS'): ['12345 13 2 ABCDEF'],
        ('example.com', 'DNSKEY'): ['257 3 13 xyz'],
        ('_mta-sts.example.com', 'TXT'): ['v=STSv1; id=1'],
        ('_smtp._tls.example.com', 'TXT'): ['v=TLSRPTv1; rua=mailto:t@example.com'],
        ('example.com', 'CAA'): ['0 issue "letsencrypt.org"'],
    }
    monkeypatch.setattr(resolver, 'resolve', _fake_dns(records))
    monkeypatch.setattr(resolver, 'dnssec_validated', lambda name: True)
    monkeypatch.setattr(dns_security, 'fetch_mta_sts_policy',
                        lambda d: {'ok': True, 'policy': {'mode': 'enforce', 'mx': ['mx.example.com']}})

    report = dns_security.analyse('https://Example.com/')
    assert report['domain'] == 'example.com'
    assert report['grade'] == 'A+'
    assert report['sections']['dkim']['selectors'][0]['key_bits_approx'] == 2048
    assert not report['recommendations']


def test_dns_security_weak_domain(monkeypatch):
    from services import resolver
    from tools import dns_security

    records = {('weak.test', 'TXT'): ['v=spf1 +all']}
    monkeypatch.setattr(resolver, 'resolve', _fake_dns(records))
    monkeypatch.setattr(resolver, 'dnssec_validated', lambda name: None)

    report = dns_security.analyse('weak.test')
    titles = [c['title'] for s in report['sections'].values() for c in s['checks']]
    assert 'SPF terlalu longgar (+all)' in titles
    assert 'DMARC tidak ada' in titles
    assert report['grade'] in ('D', 'F')
    assert report['recommendations']


def test_spf_lookup_count():
    from tools import dns_security

    parsed = dns_security.parse_spf('v=spf1 ' + ' '.join(f'include:s{i}.test' for i in range(11)) + ' ~all')
    assert parsed['lookups'] == 11
    assert parsed['all'] == '~'


def test_dns_security_route(client, monkeypatch):
    from tools import dns_security

    monkeypatch.setattr(dns_security, 'analyse', lambda d: {
        'domain': d, 'score': 50, 'grade': 'D', 'recommendations': ['Tambahkan DMARC'],
        'sections': {'spf': {'records': [], 'checks': [
            {'status': 'fail', 'title': 'SPF tidak ada', 'detail': '-', 'weight': 20,
             'recommendation': 'Tambahkan DMARC'}]}},
    })
    response = client.post('/dns-security', data={'domain': 'example.com'})
    assert response.status_code == 200
    assert b'SPF tidak ada' in response.data
    assert b'grade-d' in response.data


# ── 1.5 Security headers & TLS ──

class _Headers(dict):
    def getlist(self, name):
        return self.get('_cookies', [])


class _Resp:
    def __init__(self, url, headers, cookies=()):
        self.url = url
        self.status_code = 200
        self.headers = headers
        self.history = []
        self.raw = type('Raw', (), {'headers': _Headers(_cookies=list(cookies))})()


def test_headers_grader_strong(monkeypatch):
    from tools import web_security

    headers = {
        'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
        'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'Permissions-Policy': 'camera=()',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Resource-Policy': 'same-origin',
    }
    monkeypatch.setattr(web_security.requests, 'get',
                        lambda url, **kw: _Resp('https://example.com/', headers,
                                                ['sid=1; Secure; HttpOnly; SameSite=Lax']))
    report = web_security.analyse_headers('example.com')
    assert report['grade'] == 'A+'
    xfo = next(c for c in report['checks'] if c['header'] == 'x-frame-options')
    assert xfo['status'] == 'pass'
    assert report['cookies'][0]['samesite'] == 'lax'


def test_headers_grader_weak(monkeypatch):
    from tools import web_security

    monkeypatch.setattr(web_security.requests, 'get',
                        lambda url, **kw: _Resp('http://example.com/',
                                                {'Server': 'Apache/2.4.1', 'X-Powered-By': 'PHP/5.6'}))
    report = web_security.analyse_headers('http://example.com')
    assert report['grade'] == 'F'
    assert {leak['header'] for leak in report['leaks']} == {'server', 'x-powered-by'}
    assert all(c['status'] == 'fail' for c in report['checks'])


def test_web_security_route(client, monkeypatch):
    from tools import web_security

    monkeypatch.setattr(web_security, 'analyse', lambda url: {
        'url': url, 'final_url': url, 'status_code': 200, 'redirects': [], 'https': True,
        'score': 90, 'grade': 'A', 'checks': [], 'leaks': [], 'cookies': [], 'raw_headers': {},
        'cert_error': None, 'tls_error': None,
        'tls': {'host': 'example.com', 'port': 443, 'verified': True,
                'subject': {'commonName': 'example.com'}, 'issuer': {'commonName': 'Test CA'},
                'serial': 'ABC', 'not_before': '2026-01-01T00:00:00', 'not_after': '2027-01-01T00:00:00',
                'days_left': 120, 'sans': ['example.com'], 'protocol': 'TLSv1.3',
                'cipher': 'TLS_AES_256_GCM_SHA384', 'cipher_bits': 256, 'issues': []},
    })
    response = client.post('/web-security', data={'url': 'https://example.com'})
    assert response.status_code == 200
    assert b'Test CA' in response.data
    assert b'TLSv1.3' in response.data


# ── 1.6 RDAP + WHOIS fallback ──

RDAP_SAMPLE = {
    'ldhName': 'EXAMPLE.COM',
    'status': ['client transfer prohibited'],
    'events': [
        {'eventAction': 'registration', 'eventDate': '1995-08-14T04:00:00Z'},
        {'eventAction': 'expiration', 'eventDate': '2030-08-13T04:00:00Z'},
    ],
    'nameservers': [{'ldhName': 'B.IANA-SERVERS.NET'}, {'ldhName': 'A.IANA-SERVERS.NET'}],
    'secureDNS': {'delegationSigned': True},
    'entities': [{
        'roles': ['registrar'],
        'vcardArray': ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'RESERVED-IANA']]],
        'publicIds': [{'type': 'IANA Registrar ID', 'identifier': '376'}],
        'entities': [{
            'roles': ['abuse'],
            'vcardArray': ['vcard', [['email', {}, 'text', 'abuse@iana.org']]],
        }],
    }],
}


def test_parse_rdap():
    from tools import domain_tool

    parsed = domain_tool.parse_rdap(RDAP_SAMPLE)
    assert parsed['domain'] == 'example.com'
    assert parsed['registrar'] == 'RESERVED-IANA'
    assert parsed['registrar_iana_id'] == '376'
    assert parsed['abuse_email'] == 'abuse@iana.org'
    assert parsed['name_servers'] == ['a.iana-servers.net', 'b.iana-servers.net']
    assert parsed['dnssec'] is True


def test_domain_falls_back_to_whois(monkeypatch):
    from tools import domain_tool

    def rdap_fail(domain):
        raise LookupError('no rdap')

    monkeypatch.setattr(domain_tool, 'rdap_lookup', rdap_fail)
    monkeypatch.setattr(domain_tool, 'whois_lookup', lambda d: {'source': 'WHOIS', 'domain': d,
                                                                 'registrar': 'X'})
    monkeypatch.setattr(domain_tool.socket, 'gethostbyname', lambda d: '127.0.0.1')
    result = domain_tool.lookup('https://www.Example.org/path')
    assert result['source'] == 'WHOIS'
    assert result['domain'] == 'example.org'
    assert 'no rdap' in result['fallback_reason']


def test_domain_route_shows_rdap(client, monkeypatch):
    from tools import domain_tool

    def fake_lookup(d):
        result = domain_tool.parse_rdap(RDAP_SAMPLE)
        result.update(ip='93.184.216.34', fallback_reason=None)
        return result

    monkeypatch.setattr(domain_tool, 'lookup', fake_lookup)
    response = client.post('/domain', data={'domain': 'example.com'})
    assert response.status_code == 200
    assert b'Sumber: RDAP' in response.data
    assert b'abuse@iana.org' in response.data


# ── 1.8 UI: export toolbar & prefill ──

def test_export_toolbar_rendered(client, monkeypatch):
    from tools import dns_tool

    monkeypatch.setattr(dns_tool, 'resolve_all', lambda d: {'A': ['1.2.3.4']})
    response = client.post('/dns', data={'domain': 'example.com'})
    assert b'data-export="csv"' in response.data
    assert b'data-export="json"' in response.data
    assert b'id="result-data"' in response.data


def test_navbar_has_unified_search(client):
    response = client.get('/phone')
    assert b'action="/search"' in response.data


def test_csrf_header_accepted_for_json_endpoints(client, monkeypatch):
    from tools import wmn_tool

    monkeypatch.setattr(wmn_tool, 'update_dataset', lambda: 600)
    flask_app.config['CSRF_ENABLED'] = True
    try:
        assert client.post('/username/update-dataset').status_code == 400
        with client.session_transaction() as session:
            session['_csrf_token'] = 't'
        response = client.post('/username/update-dataset', headers={'X-CSRF-Token': 't'})
        assert response.get_json() == {'success': True, 'total': 600}
    finally:
        flask_app.config['CSRF_ENABLED'] = False
