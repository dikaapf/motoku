"""Tests for S4 people, image & geo. All network access is faked."""

import io
from datetime import datetime, timedelta, timezone

import pytest


class FakeResp:
    def __init__(self, payload=None, status=200, text=None, headers=None):
        self._payload = payload
        self.status_code = status
        self.ok = status < 400
        self.text = text if text is not None else ''
        self.headers = headers or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(str(self.status_code))


# ── 4.1 phone ──

def test_phone_indonesian_prefix_and_formats():
    from tools import phone_tool

    r = phone_tool.track('0817 1234 5678')
    assert r['e164'] == '+6281712345678'
    assert r['operator_prefix'] == 'XL Axiata'
    assert r['prefix'] == '0817'
    assert '081712345678' in r['formats'] and '+62 817-1234-5678' in r['formats']
    labels = [m['label'] for m in r['footprint']['messengers']]
    assert 'WhatsApp (wa.me)' in labels
    wa = next(m for m in r['footprint']['messengers'] if m['label'].startswith('WhatsApp'))
    assert wa['url'] == 'https://wa.me/6281712345678'


def test_phone_invalid_input():
    from tools import phone_tool

    with pytest.raises(ValueError):
        phone_tool.track('not a number')


def test_phone_route_shows_footprint(client):
    body = client.post('/phone', data={'number': '+6281234567890'}).data
    assert b'wa.me/6281234567890' in body
    assert b'Telkomsel' in body
    assert b'tidak dicek otomatis' in body


# ── 4.2 image ──

def _jpeg_with_gps():
    from PIL import ExifTags, Image

    img = Image.new('RGB', (40, 30), (10, 200, 30))
    exif = Image.Exif()
    exif[0x010f] = 'Canon'
    exif[0x0110] = 'EOS 80D'
    exif[0x0131] = 'GIMP 2.10'
    exif[ExifTags.IFD.GPSInfo] = {1: 'S', 2: (6.0, 10.0, 30.0), 3: 'E', 4: (106.0, 49.0, 0.0)}
    buf = io.BytesIO()
    img.save(buf, 'JPEG', exif=exif)
    return buf.getvalue()


def test_image_exif_gps_and_hashes():
    pytest.importorskip('PIL')
    from tools import image_tool

    report = image_tool.analyse(_jpeg_with_gps(), 'x.jpg', with_ocr=False)
    assert report['gps']['lat'] == -6.175
    assert round(report['gps']['lng'], 4) == 106.8167
    assert report['exif_key']['Model'] == 'EOS 80D'
    assert len(report['hashes']['sha256']) == 64 and len(report['hashes']['dhash']) == 16
    assert any('editor' in w for w in report['warnings'])
    assert any('GPS' in w for w in report['warnings'])


def test_image_without_exif_warns():
    from PIL import Image

    from tools import image_tool

    buf = io.BytesIO()
    Image.new('RGB', (10, 10)).save(buf, 'PNG')
    report = image_tool.analyse(buf.getvalue(), 'a.png', with_ocr=False)
    assert report['gps'] is None
    assert any('Tidak ada EXIF' in w for w in report['warnings'])


def test_image_rejects_non_image():
    from tools import image_tool

    with pytest.raises(ValueError):
        image_tool.analyse(b'not an image at all', 'x.txt')


def test_reverse_search_links_use_url():
    from tools import image_tool

    links = image_tool.reverse_search_links('https://example.com/a b.jpg')
    tineye = next(link for link in links if link['label'] == 'TinEye')
    assert tineye['direct'] and 'https%3A%2F%2Fexample.com%2Fa%20b.jpg' in tineye['url']
    assert not any(link['direct'] for link in image_tool.reverse_search_links(None))


def test_image_upload_route(client, monkeypatch):
    from tools import geo_tool

    monkeypatch.setattr(geo_tool, 'reverse_geocode', lambda lat, lng: {'display_name': 'Monas, Jakarta'})
    resp = client.post('/image', data={'image': (io.BytesIO(_jpeg_with_gps()), 'photo.jpg')},
                       content_type='multipart/form-data')
    assert resp.status_code == 200
    assert b'Monas, Jakarta' in resp.data
    assert b'EOS 80D' in resp.data
    assert client.post('/image', data={}).status_code == 200


# ── 4.4 geo ──

@pytest.mark.parametrize('text, expected', [
    ('-6.175, 106.8272', (-6.175, 106.8272)),
    ('6°10\'30"S 106°49\'0"E', (-6.175, 106.8166667)),
    ('https://www.google.com/maps/place/x/@-6.1754,106.8272,17z', (-6.1754, 106.8272)),
])
def test_parse_coordinates(text, expected):
    from tools import geo_tool

    assert geo_tool.parse_coordinates(text) == expected


def test_parse_coordinates_rejects():
    from tools import geo_tool

    with pytest.raises(ValueError):
        geo_tool.parse_coordinates('95, 200')
    with pytest.raises(ValueError):
        geo_tool.parse_coordinates('Monas')


def test_solar_position_known_values():
    from tools import geo_tool

    # Jakarta, equinox, ~local solar noon: sun almost overhead, slightly north.
    p = geo_tool.solar_position(-6.175, 106.827, datetime(2024, 3, 20, 5, 0, tzinfo=timezone.utc))
    assert 83 < p['elevation'] < 85
    # London, summer solstice noon UTC: elevation ≈ 62°, azimuth ≈ south.
    p = geo_tool.solar_position(51.5, -0.12, datetime(2024, 6, 21, 12, 0, tzinfo=timezone.utc))
    assert abs(p['elevation'] - 61.9) < 0.3
    assert 175 < p['azimuth'] < 185


def test_sun_events_london_solstice():
    from tools import geo_tool

    ev = geo_tool.sun_events(51.5, -0.12, datetime(2024, 6, 21, tzinfo=timezone.utc))
    bst = timedelta(hours=1)
    sunrise = (ev['sunrise'] + bst).strftime('%H:%M')
    sunset = (ev['sunset'] + bst).strftime('%H:%M')
    assert sunrise in ('04:42', '04:43', '04:44', '04:45')
    assert sunset in ('21:19', '21:20', '21:21', '21:22')


def test_shadow_ratio():
    from tools import geo_tool

    assert geo_tool.shadow_ratio(45) == 1.0
    assert geo_tool.shadow_ratio(-1) is None


def test_geo_investigate(monkeypatch):
    from tools import geo_tool

    monkeypatch.setattr(geo_tool, 'reverse_geocode', lambda lat, lng: {'display_name': 'Gambir, Jakarta'})
    monkeypatch.setattr(geo_tool, 'nearby_pois', lambda lat, lng, radius: [
        {'name': 'Monumen Nasional', 'kind': 'attraction', 'lat': lat, 'lng': lng, 'distance_m': 0, 'osm': 'x'}])
    monkeypatch.delenv('MOTOKU_FIRMS_MAP_KEY', raising=False)
    r = geo_tool.investigate('-6.1754, 106.8272', when=datetime(2024, 3, 20, 12, 0), tz_offset=7)
    assert r['address']['display_name'] == 'Gambir, Jakarta'
    assert r['fires']['status'] == 'no_key'
    assert r['sun']['sunrise'] and r['sun']['sunset']
    assert any(link['label'].startswith('Copernicus') for link in r['links'])
    assert len(r['sun']['table']) == 15


def test_overpass_falls_back_between_mirrors(monkeypatch):
    from tools import geo_tool

    calls = []

    def fake_post(url, **kw):
        calls.append(url)
        if len(calls) == 1:
            return FakeResp(status=504)
        return FakeResp({'elements': [{'type': 'node', 'id': 1, 'lat': -6.1, 'lon': 106.8,
                                       'tags': {'amenity': 'police', 'name': 'Polsek'}}]})

    monkeypatch.setattr(geo_tool.requests, 'post', fake_post)
    pois = geo_tool.nearby_pois(-6.1, 106.8, 300)
    assert len(calls) == 2
    assert pois[0]['name'] == 'Polsek' and pois[0]['kind'] == 'police'


def test_geo_route(client, monkeypatch):
    from tools import geo_tool

    monkeypatch.setattr(geo_tool, 'reverse_geocode', lambda lat, lng: {'display_name': 'Somewhere'})
    monkeypatch.setattr(geo_tool, 'nearby_pois', lambda lat, lng, radius: [])
    body = client.post('/geo', data={'location': '-6.2, 106.8', 'when': '2024-03-20T09:00', 'tz': '7'}).data
    assert b'Somewhere' in body
    assert b'geo-map' in body
    assert b'Azimut' in body


# ── 4.3 corporate ──

def test_corporate_search(monkeypatch):
    from tools import corporate_tool

    monkeypatch.delenv('MOTOKU_OPENCORPORATES_TOKEN', raising=False)

    def fake_get(url, **kw):
        if 'gleif' in url:
            return FakeResp({'data': [{'attributes': {
                'lei': '254900MT2CH1Y5Y7OX6X',
                'entity': {'legalName': {'name': 'PT Contoh'}, 'status': 'ACTIVE', 'jurisdiction': 'ID',
                           'legalAddress': {'addressLines': ['Jl. Satu'], 'city': 'Jakarta', 'country': 'ID'}},
                'registration': {'status': 'ISSUED', 'initialRegistrationDate': '2023-10-30T00:00:00Z'}}}]})
        if 'orcid' in url:
            return FakeResp({'expanded-result': [{'orcid-id': '0000-0001', 'given-names': 'Ani',
                                                  'family-names': 'Putri', 'institution-name': ['ITB']}]})
        if 'openalex' in url:
            return FakeResp({'results': [{'display_name': 'Ani Putri', 'id': 'https://openalex.org/A1',
                                          'works_count': 5, 'cited_by_count': 10,
                                          'summary_stats': {'h_index': 2},
                                          'last_known_institutions': [{'display_name': 'ITB', 'country_code': 'ID'}]}]})
        raise AssertionError(url)

    monkeypatch.setattr(corporate_tool.requests, 'get', fake_get)
    r = corporate_tool.search('PT Contoh')
    assert r['results']['gleif']['items'][0]['lei'] == '254900MT2CH1Y5Y7OX6X'
    assert r['results']['gleif']['items'][0]['legal_address'] == 'Jl. Satu, Jakarta, ID'
    assert r['results']['opencorporates']['status'] == 'no_key'
    assert r['results']['orcid']['items'][0]['name'] == 'Ani Putri'
    assert r['results']['openalex']['items'][0]['institution'] == 'ITB'
    assert any('AHU' in link['label'] for link in r['links'])
    with pytest.raises(ValueError):
        corporate_tool.search('ab')


def test_corporate_route(client, monkeypatch):
    from tools import corporate_tool

    monkeypatch.setattr(corporate_tool, 'search', lambda q, kinds=(): {
        'query': q, 'links': [], 'results': {'gleif': {'status': 'ok', 'items': [
            {'lei': 'X' * 20, 'name': 'PT Uji', 'status': 'ACTIVE', 'jurisdiction': 'ID', 'registered_as': '1',
             'legal_address': 'Jakarta', 'hq_address': 'Jakarta', 'registered': '2024', 'next_renewal': '2025',
             'registration_status': 'ISSUED', 'url': 'u'}]}}})
    assert b'PT Uji' in client.post('/corporate', data={'query': 'PT Uji'}).data


# ── 4.5 social ──

def test_social_lookup_mixed(monkeypatch):
    from tools import social_tool

    monkeypatch.delenv('MOTOKU_REDDIT_CLIENT_ID', raising=False)
    monkeypatch.delenv('MOTOKU_GITHUB_TOKEN', raising=False)

    tiktok_page = ('<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__" type="application/json">'
                   '{"__DEFAULT_SCOPE__":{"webapp.user-detail":{"statusCode":0,"userInfo":{"user":'
                   '{"uniqueId":"alice","nickname":"Alice","signature":"hi","verified":false},'
                   '"stats":{"followerCount":5,"videoCount":1}}}}}</script>')

    def fake_get(url, **kw):
        if url == 'https://api.github.com/users/alice':
            return FakeResp({'login': 'alice', 'name': 'Alice', 'html_url': 'https://github.com/alice',
                             'blog': 'https://alice.dev', 'followers': 3, 'organizations_url': 'orgs'})
        if url == 'orgs':
            return FakeResp([{'login': 'acme'}])
        if 'bsky' in url:
            return FakeResp({'error': 'InvalidRequest'}, status=400)
        if 'lookup' in url:
            return FakeResp(status=404)
        if url == 'https://t.me/alice':
            return FakeResp(text='<html>no profile</html>')
        if 'tiktok' in url:
            return FakeResp(text=tiktok_page)
        raise AssertionError(url)

    monkeypatch.setattr(social_tool.requests, 'get', fake_get)
    r = social_tool.lookup('@alice')
    by = {x['platform']: x for x in r['results']}
    assert by['github']['status'] == 'ok'
    assert by['github']['profiles'][0]['extra']['organizations'] == ['acme']
    assert by['tiktok']['profiles'][0]['stats']['followers'] == 5
    assert by['bluesky']['status'] == 'not_found'
    assert by['telegram']['status'] == 'not_found'
    assert by['mastodon']['status'] == 'not_found'
    assert by['reddit']['status'] == 'no_key'
    assert r['found'] == 2
    assert {'source': 'GitHub (alice)', 'kind': 'blog', 'value': 'https://alice.dev'} in r['pivots']


def test_social_rejects_bad_username():
    from tools import social_tool

    with pytest.raises(ValueError):
        social_tool.lookup('bad name!')


def test_social_route(client, monkeypatch):
    from tools import social_tool

    monkeypatch.setattr(social_tool, 'lookup', lambda u: {'username': u, 'found': 1, 'pivots': [], 'results': [
        {'platform': 'github', 'status': 'ok', 'profiles': [
            {'platform': 'GitHub', 'username': u, 'name': 'Alice', 'url': 'https://github.com/alice', 'stats': {}}]}]})
    body = client.post('/social', data={'username': 'alice'}).data
    assert b'https://github.com/alice' in body
    assert 'belum tentu orang yang sama'.encode() in body


# ── DoD: unified search integration ──

@pytest.mark.parametrize('query, kind, first', [
    ('-6.175, 106.827', 'coords', 'geo'),
    ('https://cdn.example.com/photo.JPG', 'image_url', 'image'),
    ('254900LG0T6W3FFZRJ63', 'lei', 'corporate'),
    ('torvalds', 'username', 'social'),
    ('Budi Santoso', 'name', 'search_person'),
    ('+6281234567890', 'phone', 'phone'),
])
def test_unified_search_routes_s4(query, kind, first):
    from services import detect

    routing = detect.routes_for(query)
    assert routing['type'] == kind
    assert routing['tools'][0]['endpoint'] == first


def test_search_page_links_geo(client):
    body = client.get('/search?q=-6.175,%20106.827').data
    assert b'/geo?q=' in body


@pytest.mark.parametrize('path', ['/image', '/geo', '/corporate', '/social'])
def test_s4_pages_render(client, path):
    assert client.get(path).status_code == 200
