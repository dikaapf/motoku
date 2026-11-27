import builtins
import json

import pytest

from app import app as flask_app


@pytest.mark.parametrize('path', [
    '/',
    '/phone',
    '/ip',
    '/username',
    '/username-deep',
    '/email',
    '/domain',
    '/dns',
    '/dns-security',
    '/web-security',
    '/portscan',
    '/tech',
    '/subdomain',
    '/dorks',
    '/search-person',
    '/location-tracker',
    '/cctv',
    '/flight-radar',
    '/status',
])
def test_pages_render(client, path):
    response = client.get(path)
    assert response.status_code == 200


def test_index_contains_brand(client):
    response = client.get('/')
    assert b'Motoku' in response.data


def test_security_headers(client):
    response = client.get('/')
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert response.headers['X-Frame-Options'] == 'SAMEORIGIN'


def test_dns_route_uses_tool(client, monkeypatch):
    from tools import dns_tool

    fake = {
        'A': ['93.184.216.34'],
        'AAAA': [],
        'MX': [],
        'NS': ['a.iana-servers.net.'],
        'TXT': ['"v=spf1 -all"'],
        'CNAME': [],
        'SOA': [],
        'CAA': [],
        'SRV': [],
        'SPF': ['"v=spf1 -all"'],
        'DMARC': ['"v=DMARC1; p=none"'],
        'DKIM': [],
        'DNSSEC': [],
    }
    monkeypatch.setattr(dns_tool, 'resolve_all', lambda domain: fake)

    response = client.post('/dns', data={'domain': 'example.com'})
    assert response.status_code == 200
    assert b'93.184.216.34' in response.data
    assert b'DMARC' in response.data


def test_dns_spf_and_dmarc_parsing(monkeypatch):
    from tools import dns_tool

    def fake_resolve(domain, record_type='A'):
        if record_type == 'TXT':
            return ['"v=spf1 include:_spf.google.com -all"']
        return []

    def fake_optional(name, record_type):
        if name.startswith('_dmarc.'):
            return ['"v=DMARC1; p=reject"']
        return []

    monkeypatch.setattr(dns_tool, 'resolve', fake_resolve)
    monkeypatch.setattr(dns_tool, '_resolve_optional', fake_optional)

    results = dns_tool.resolve_all('example.com')
    assert results['SPF'] == ['"v=spf1 include:_spf.google.com -all"']
    assert results['DMARC'] == ['"v=DMARC1; p=reject"']
    assert 'SPF' not in dns_tool.RECORD_TYPES


def test_tech_tool_normalises_wappalyzer_output(monkeypatch):
    from tools import tech_tool

    class FakeWappalyzer:
        def analyze_with_versions_and_categories(self, webpage):
            return {
                'Nginx': {'versions': ['1.25.3'], 'categories': ['Web servers']},
                'Unknown': {'versions': [], 'categories': []},
            }

        def get_confidence(self, name):
            return 300 if name == 'Nginx' else []

    class FakeWebPage:
        @staticmethod
        def new_from_url(url, timeout=10):
            return object()

    class FakeWappalyzerClass:
        @staticmethod
        def latest():
            return FakeWappalyzer()

    monkeypatch.setattr(tech_tool, 'Wappalyzer', FakeWappalyzerClass)
    monkeypatch.setattr(tech_tool, 'WebPage', FakeWebPage)

    results = tech_tool.detect('example.com')
    by_name = {item['name']: item for item in results}
    assert by_name['Nginx']['version'] == '1.25.3'
    assert by_name['Nginx']['confidence'] == '100%'
    assert by_name['Unknown']['version'] == '-'
    assert by_name['Unknown']['confidence'] == '-'


def test_ip_tool_uses_https(monkeypatch):
    from tools import ip_tool

    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                'success': True,
                'latitude': 1.0,
                'longitude': 2.0,
                'connection': {},
                'timezone': {},
            }

    def fake_get(url, timeout=None):
        captured['url'] = url
        captured['timeout'] = timeout
        return FakeResponse()

    monkeypatch.setattr(ip_tool.requests, 'get', fake_get)

    result = ip_tool.track('8.8.8.8')
    assert captured['url'].startswith('https://')
    assert captured['timeout'] == ip_tool.TIMEOUT
    assert result['maps_url'].startswith('https://www.google.com/maps/')


def test_deep_username_degrades_gracefully(monkeypatch):
    from tools import deep_username

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith('sherlock_project'):
            raise ImportError('not installed')
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, '__import__', fake_import)

    result = deep_username.sherlock_search('someone')
    assert result['total_found'] == 0
    assert 'belum terpasang' in result['error']


# ── CSRF ──

def test_csrf_rejects_post_without_token(client):
    flask_app.config['CSRF_ENABLED'] = True
    try:
        response = client.post('/dns', data={'domain': 'example.com'})
        assert response.status_code == 400
    finally:
        flask_app.config['CSRF_ENABLED'] = False


def test_csrf_accepts_valid_token(client, monkeypatch):
    from tools import dns_tool

    empty = {
        key: []
        for key in (
            'A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA',
            'SRV', 'SPF', 'DMARC', 'DKIM', 'DNSSEC',
        )
    }
    monkeypatch.setattr(dns_tool, 'resolve_all', lambda domain: empty)

    flask_app.config['CSRF_ENABLED'] = True
    try:
        with client.session_transaction() as session:
            session['_csrf_token'] = 'test-token'
        response = client.post(
            '/dns',
            data={'domain': 'example.com', 'csrf_token': 'test-token'},
        )
        assert response.status_code == 200
    finally:
        flask_app.config['CSRF_ENABLED'] = False


# ── Rate limiting ──

def test_rate_limit_blocks_after_threshold(client):
    import rate_limit

    flask_app.config.update(
        RATE_LIMIT_ENABLED=True,
        RATE_LIMIT_REQUESTS=2,
        RATE_LIMIT_WINDOW=60,
    )
    try:
        assert client.get('/').status_code == 200
        assert client.get('/').status_code == 200
        response = client.get('/')
        assert response.status_code == 429
        assert response.headers['Retry-After']
    finally:
        flask_app.config.update(
            RATE_LIMIT_ENABLED=False,
            RATE_LIMIT_REQUESTS=120,
            RATE_LIMIT_WINDOW=60,
        )
        rate_limit.reset()


# ── SQLite persistence ──

def test_tracking_crud():
    import db

    db.create_tracking('abc123', 'Test')
    track = db.get_tracking('abc123')
    assert track['status'] == 'pending'
    assert track['location'] is None

    db.update_tracking_location('abc123', {'lat': 1.0, 'lng': 2.0}, {'os': 'test'})
    track = db.get_tracking('abc123')
    assert track['status'] == 'success'
    assert track['location']['lat'] == 1.0
    assert track['device_info']['os'] == 'test'
    assert any(tracking_id == 'abc123' for tracking_id, _ in db.list_tracking())


def test_location_tracker_flow(client):
    response = client.post('/location-tracker', data={'label': 'Test'})
    assert response.status_code == 302

    tracking_id = response.headers['Location'].rstrip('/').split('/')[-2]
    response = client.post(
        f'/api/location/{tracking_id}',
        json={
            'lat': -6.2,
            'lng': 106.8,
            'accuracy': 10,
            'device_info': {'os': 'test'},
        },
    )
    assert response.status_code == 200
    assert response.get_json() == {'ok': True}


def test_provider_usage_recorded():
    import db

    db.record_provider_call('example.test', success=True)
    db.record_provider_call('example.test', success=False)
    usage = {item['provider']: item for item in db.provider_usage()}
    assert usage['example.test']['calls'] == 2
    assert usage['example.test']['errors'] == 1


def test_legacy_json_migration(tmp_path, monkeypatch):
    import db

    tracking_file = tmp_path / 'tracking.json'
    tracking_file.write_text(json.dumps({
        'legacy1': {
            'label': 'Legacy',
            'created_at': '2026-01-01 00:00:00',
            'status': 'pending',
            'location': None,
        },
    }))
    cameras_file = tmp_path / 'cameras.json'
    cameras_file.write_text(json.dumps({
        'cameras': [{'id': 'cam1', 'name': 'Camera', 'city': 'Jakarta'}],
    }))

    monkeypatch.setattr(db, 'LEGACY_TRACKING_FILE', str(tracking_file))
    monkeypatch.setattr(db, 'LEGACY_CAMERAS_FILE', str(cameras_file))
    db.configure(str(tmp_path / 'migrate.db'), migrate=True)

    assert db.get_tracking('legacy1')['label'] == 'Legacy'
    assert db.get_camera('cam1')['city'] == 'Jakarta'
