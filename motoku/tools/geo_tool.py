"""Geolocation toolkit: coordinate parsing, reverse/forward geocoding (OSM
Nominatim), nearby POIs (Overpass), NASA FIRMS fire hotspots, satellite /
street-level links and a NOAA solar-position calculator for chronolocation
(sun azimuth/elevation and shadow length at a given place and time).
"""

import math
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone

import requests

from services.providers import registry as R

UA = {'User-Agent': 'Motoku-OSINT/1.4 (self-hosted OSINT toolkit; https://github.com/)'}
DEFAULT_OVERPASS = ('https://overpass-api.de/api/interpreter,'
                    'https://maps.mail.ru/osm/tools/overpass/api/interpreter,'
                    'https://overpass.kumi.systems/api/interpreter')
OVERPASS_ENDPOINTS = [e.strip() for e in (os.environ.get('MOTOKU_OVERPASS_URLS') or DEFAULT_OVERPASS).split(',')
                      if e.strip()]
_nominatim_lock = threading.Lock()
_nominatim_last = [0.0]


# ── coordinates ──
DMS_RE = re.compile(
    r"""(?P<deg>\d{1,3})[°\s]+(?P<min>\d{1,2})['′\s]+(?P<sec>\d{1,2}(?:\.\d+)?)["″\s]*(?P<hem>[NSEWUTBLnsewutbl])""")


def parse_coordinates(text):
    """Parse '-6.175, 106.8272', '6°10'30"S 106°49'0"E' or a Google Maps URL."""
    t = (text or '').strip()
    m = re.search(r'@(-?\d+\.\d+),(-?\d+\.\d+)', t) or re.search(r'[?&](?:q|ll|query)=(-?\d+\.\d+),\s*(-?\d+\.\d+)', t)
    if m:
        lat, lng = float(m.group(1)), float(m.group(2))
    else:
        dms = list(DMS_RE.finditer(t))
        if len(dms) == 2:
            vals = []
            for d in dms:
                v = int(d['deg']) + int(d['min']) / 60 + float(d['sec']) / 3600
                hem = d['hem'].upper()
                if hem in ('S', 'W', 'B'):  # B = Barat (ID), S = Selatan
                    v = -v
                vals.append((hem, v))
            lat = next((v for h, v in vals if h in ('N', 'S', 'U')), vals[0][1])
            lng = next((v for h, v in vals if h in ('E', 'W', 'T', 'B')), vals[1][1])
        else:
            m = re.match(r'^\s*(-?\d{1,2}(?:\.\d+)?)\s*[,;\s]\s*(-?\d{1,3}(?:\.\d+)?)\s*$', t)
            if not m:
                raise ValueError('Format koordinat tidak dikenali (contoh: -6.175, 106.827)')
            lat, lng = float(m.group(1)), float(m.group(2))
    if not (-90 <= lat <= 90 and -180 <= lng <= 180):
        raise ValueError('Koordinat di luar jangkauan')
    return round(lat, 7), round(lng, 7)


def looks_like_coordinates(text):
    try:
        parse_coordinates(text)
        return True
    except ValueError:
        return False


# ── Nominatim ──
def _nominatim(path, params):
    def run():
        with _nominatim_lock:  # usage policy: max 1 request per second
            wait = 1.0 - (time.monotonic() - _nominatim_last[0])
            if wait > 0:
                time.sleep(wait)
            _nominatim_last[0] = time.monotonic()
            resp = requests.get(f'https://nominatim.openstreetmap.org/{path}',
                                params={**params, 'format': 'jsonv2', 'accept-language': 'id,en'},
                                headers=UA, timeout=15)
        resp.raise_for_status()
        return resp.json()
    return R.NOMINATIM.fetch((path, sorted(params.items())), run)


def reverse_geocode(lat, lng):
    d = _nominatim('reverse', {'lat': lat, 'lon': lng, 'zoom': 18, 'addressdetails': 1})
    if not d or d.get('error'):
        return None
    return {'display_name': d.get('display_name'), 'address': d.get('address', {}),
            'osm': f'https://www.openstreetmap.org/{d.get("osm_type")}/{d.get("osm_id")}' if d.get('osm_id') else None,
            'category': d.get('category'), 'type': d.get('type')}


def geocode(query, limit=5):
    rows = _nominatim('search', {'q': query, 'limit': limit, 'addressdetails': 1})
    return [{'display_name': r.get('display_name'), 'lat': float(r['lat']), 'lng': float(r['lon']),
             'type': r.get('type'), 'category': r.get('category')} for r in rows]


# ── Overpass ──
POI_FILTERS = {
    'amenity': '["amenity"~"police|hospital|school|university|place_of_worship|bank|fuel|townhall|courthouse|embassy|restaurant|cafe"]',
    'tourism': '["tourism"]',
    'transport': '["railway"~"station|halt"]',
    'shop': '["shop"~"mall|supermarket|department_store"]',
    'telecom': '["man_made"~"mast|tower"]',
}


def nearby_pois(lat, lng, radius=500, limit=60):
    radius = max(50, min(int(radius), 3000))
    parts = ''.join(f'nwr{flt}(around:{radius},{lat},{lng});' for flt in POI_FILTERS.values())
    query = f'[out:json][timeout:25];({parts});out center {limit};'

    def run():
        last_error = None
        for endpoint in OVERPASS_ENDPOINTS:
            try:
                resp = requests.post(endpoint, data={'data': query}, headers=UA, timeout=30)
                if resp.status_code in (429, 502, 503, 504):
                    last_error = f'{endpoint}: HTTP {resp.status_code}'
                    continue
                resp.raise_for_status()
                return resp.json().get('elements', [])
            except requests.RequestException as e:
                last_error = f'{endpoint}: {type(e).__name__}'
        raise ValueError(f'Semua endpoint Overpass gagal ({last_error})')

    elements = R.OVERPASS.fetch((round(lat, 5), round(lng, 5), radius), run)
    pois = []
    for el in elements:
        tags = el.get('tags', {})
        plat = el.get('lat') or (el.get('center') or {}).get('lat')
        plng = el.get('lon') or (el.get('center') or {}).get('lon')
        if plat is None:
            continue
        kind = next((tags[k] for k in ('amenity', 'tourism', 'railway', 'shop', 'man_made') if k in tags), '?')
        pois.append({'name': tags.get('name') or tags.get('name:en') or f'({kind})', 'kind': kind,
                     'lat': plat, 'lng': plng, 'distance_m': round(haversine(lat, lng, plat, plng)),
                     'osm': f'https://www.openstreetmap.org/{el["type"]}/{el["id"]}'})
    pois.sort(key=lambda p: p['distance_m'])
    return pois


def haversine(lat1, lng1, lat2, lng2):
    r = 6371000
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lng2 - lng1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


# ── NASA FIRMS ──
def firms_hotspots(lat, lng, days=2, box_km=25):
    if not R.FIRMS.configured:
        return {'status': 'no_key', 'message': f'Set {R.FIRMS.key_env} untuk data titik api NASA FIRMS'}
    dlat = box_km / 111.0
    dlng = box_km / (111.0 * max(0.1, math.cos(math.radians(lat))))
    area = f'{lng - dlng:.4f},{lat - dlat:.4f},{lng + dlng:.4f},{lat + dlat:.4f}'
    days = max(1, min(int(days), 5))

    def run():
        url = f'https://firms.modaps.eosdis.nasa.gov/api/area/csv/{R.FIRMS.api_key}/VIIRS_SNPP_NRT/{area}/{days}'
        resp = requests.get(url, headers=UA, timeout=30)
        resp.raise_for_status()
        lines = [x for x in resp.text.strip().splitlines() if x]
        if not lines or ',' not in lines[0]:
            raise ValueError(resp.text[:120] or 'Respons FIRMS kosong')
        header = lines[0].split(',')
        return [dict(zip(header, row.split(','))) for row in lines[1:]]

    rows = R.FIRMS.fetch((area, days), run)
    points = [{'lat': float(r['latitude']), 'lng': float(r['longitude']), 'date': r.get('acq_date'),
               'time': r.get('acq_time'), 'confidence': r.get('confidence'), 'frp': r.get('frp'),
               'distance_km': round(haversine(lat, lng, float(r['latitude']), float(r['longitude'])) / 1000, 1)}
              for r in rows if r.get('latitude')]
    points.sort(key=lambda p: p['distance_km'])
    return {'status': 'ok', 'count': len(points), 'points': points[:100], 'days': days, 'box_km': box_km}


# ── Solar position (NOAA algorithm) ──
def solar_position(lat, lng, when_utc):
    """Return sun azimuth (deg from north, clockwise) and elevation (deg)."""
    if when_utc.tzinfo is None:
        when_utc = when_utc.replace(tzinfo=timezone.utc)
    when_utc = when_utc.astimezone(timezone.utc)
    jd = (when_utc - datetime(2000, 1, 1, 12, tzinfo=timezone.utc)).total_seconds() / 86400 + 2451545.0
    jc = (jd - 2451545.0) / 36525
    geom_mean_long = (280.46646 + jc * (36000.76983 + jc * 0.0003032)) % 360
    geom_mean_anom = 357.52911 + jc * (35999.05029 - 0.0001537 * jc)
    ecc = 0.016708634 - jc * (0.000042037 + 0.0000001267 * jc)
    m = math.radians(geom_mean_anom)
    eq_ctr = (math.sin(m) * (1.914602 - jc * (0.004817 + 0.000014 * jc))
              + math.sin(2 * m) * (0.019993 - 0.000101 * jc) + math.sin(3 * m) * 0.000289)
    true_long = geom_mean_long + eq_ctr
    omega = 125.04 - 1934.136 * jc
    app_long = true_long - 0.00569 - 0.00478 * math.sin(math.radians(omega))
    mean_obliq = 23 + (26 + (21.448 - jc * (46.815 + jc * (0.00059 - jc * 0.001813))) / 60) / 60
    obliq = mean_obliq + 0.00256 * math.cos(math.radians(omega))
    decl = math.degrees(math.asin(math.sin(math.radians(obliq)) * math.sin(math.radians(app_long))))
    y = math.tan(math.radians(obliq / 2)) ** 2
    l0 = math.radians(geom_mean_long)
    eq_time = 4 * math.degrees(
        y * math.sin(2 * l0) - 2 * ecc * math.sin(m) + 4 * ecc * y * math.sin(m) * math.cos(2 * l0)
        - 0.5 * y * y * math.sin(4 * l0) - 1.25 * ecc * ecc * math.sin(2 * m))
    minutes = when_utc.hour * 60 + when_utc.minute + when_utc.second / 60
    true_solar = (minutes + eq_time + 4 * lng) % 1440
    hour_angle = true_solar / 4 - 180 if true_solar / 4 >= 0 else true_solar / 4 + 180
    lat_r, decl_r, ha_r = math.radians(lat), math.radians(decl), math.radians(hour_angle)
    cos_zenith = math.sin(lat_r) * math.sin(decl_r) + math.cos(lat_r) * math.cos(decl_r) * math.cos(ha_r)
    zenith = math.degrees(math.acos(max(-1, min(1, cos_zenith))))
    elevation = 90 - zenith
    # Atmospheric refraction correction
    if elevation > 85:
        refr = 0
    elif elevation > 5:
        te = math.tan(math.radians(elevation))
        refr = 58.1 / te - 0.07 / te ** 3 + 0.000086 / te ** 5
    elif elevation > -0.575:
        refr = 1735 + elevation * (-518.2 + elevation * (103.4 + elevation * (-12.79 + elevation * 0.711)))
    else:
        refr = -20.772 / math.tan(math.radians(elevation))
    elevation += refr / 3600
    az_den = math.cos(lat_r) * math.sin(math.radians(zenith))
    if abs(az_den) < 1e-9:
        azimuth = 180.0
    else:
        az = math.degrees(math.acos(max(-1, min(1, ((math.sin(lat_r) * math.cos(math.radians(zenith))) - math.sin(decl_r)) / az_den))))
        azimuth = (az + 180) % 360 if hour_angle > 0 else (540 - az) % 360
    return {'azimuth': round(azimuth, 2), 'elevation': round(elevation, 2), 'declination': round(decl, 3),
            'equation_of_time_min': round(eq_time, 2), 'solar_noon_utc_min': 720 - 4 * lng - eq_time}


def shadow_ratio(elevation):
    """Shadow length / object height. None when the sun is below the horizon."""
    if elevation <= 0:
        return None
    return round(1 / math.tan(math.radians(elevation)), 3)


# solar_position() already applies refraction, so sunrise/sunset is when the
# *apparent* centre is one solar radius (~0.267°) below the horizon.
HORIZON = -0.2667


def sun_events(lat, lng, day_utc):
    """Sunrise/sunset/solar noon (UTC) for a date by scanning elevation crossings."""
    start = datetime(day_utc.year, day_utc.month, day_utc.day, tzinfo=timezone.utc) - timedelta(hours=lng / 15)
    events = {'sunrise': None, 'sunset': None}
    prev = solar_position(lat, lng, start)['elevation']
    t = start
    for _ in range(24 * 12):
        t2 = t + timedelta(minutes=5)
        cur = solar_position(lat, lng, t2)['elevation']
        if prev < HORIZON <= cur and not events['sunrise']:
            events['sunrise'] = _refine(lat, lng, t, t2, rising=True)
        if prev >= HORIZON > cur and not events['sunset']:
            events['sunset'] = _refine(lat, lng, t, t2, rising=False)
        prev, t = cur, t2
    noon_min = solar_position(lat, lng, start)['solar_noon_utc_min']
    events['solar_noon'] = datetime(day_utc.year, day_utc.month, day_utc.day, tzinfo=timezone.utc) + timedelta(minutes=noon_min)
    return events


def _refine(lat, lng, a, b, rising):
    for _ in range(12):
        mid = a + (b - a) / 2
        above = solar_position(lat, lng, mid)['elevation'] >= HORIZON
        if above == rising:
            b = mid
        else:
            a = mid
    return a + (b - a) / 2


def sun_table(lat, lng, when_local, tz_offset_hours):
    """Sun position for each hour of the local day (for shadow matching)."""
    tz = timezone(timedelta(hours=tz_offset_hours))
    day = when_local.replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=tz)
    rows = []
    for h in range(5, 20):
        t = day + timedelta(hours=h)
        p = solar_position(lat, lng, t)
        rows.append({'time': t.strftime('%H:%M'), 'azimuth': p['azimuth'], 'elevation': p['elevation'],
                     'shadow_ratio': shadow_ratio(p['elevation']),
                     'shadow_azimuth': round((p['azimuth'] + 180) % 360, 1) if p['elevation'] > 0 else None})
    return rows


def map_links(lat, lng, zoom=17):
    return [
        ('OpenStreetMap', f'https://www.openstreetmap.org/?mlat={lat}&mlon={lng}#map={zoom}/{lat}/{lng}'),
        ('Google Maps', f'https://www.google.com/maps/search/?api=1&query={lat},{lng}'),
        ('Google Street View', f'https://www.google.com/maps/@?api=1&map_action=pano&viewpoint={lat},{lng}'),
        ('Google Earth', f'https://earth.google.com/web/@{lat},{lng},150a,800d,35y,0h,0t,0r'),
        ('Bing Maps', f'https://www.bing.com/maps?cp={lat}~{lng}&lvl={zoom}&style=h'),
        ('Yandex Maps', f'https://yandex.com/maps/?ll={lng},{lat}&z={zoom}&l=sat'),
        ('Apple Maps', f'https://maps.apple.com/?ll={lat},{lng}&z={zoom}'),
        ('Mapillary (street-level)', f'https://www.mapillary.com/app/?lat={lat}&lng={lng}&z={zoom}'),
        ('Wikimapia', f'https://wikimapia.org/#lat={lat}&lon={lng}&z={zoom}'),
        ('Copernicus Browser (Sentinel)', f'https://browser.dataspace.copernicus.eu/?zoom=14&lat={lat}&lng={lng}'),
        ('Sentinel Hub EO Browser', f'https://apps.sentinel-hub.com/eo-browser/?zoom=14&lat={lat}&lng={lng}'),
        ('NASA Worldview', f'https://worldview.earthdata.nasa.gov/?v={lng - 0.2},{lat - 0.15},{lng + 0.2},{lat + 0.15}'),
        ('FIRMS Fire Map', f'https://firms.modaps.eosdis.nasa.gov/map/#d:24hrs;@{lng},{lat},12z'),
        ('SunCalc', f'https://www.suncalc.org/#/{lat},{lng},17/'),
        ('PeakVisor (horizon)', f'https://peakvisor.com/panorama.html?lat={lat}&lng={lng}'),
    ]


def investigate(text, when=None, tz_offset=None, radius=500, with_pois=True, with_fires=True):
    """Resolve ``text`` (coordinates or a place name) and gather geo intel."""
    candidates = []
    try:
        lat, lng = parse_coordinates(text)
    except ValueError:
        candidates = geocode(text)
        if not candidates:
            raise ValueError('Lokasi tidak ditemukan. Masukkan koordinat atau nama tempat.')
        lat, lng = candidates[0]['lat'], candidates[0]['lng']

    if tz_offset is None:
        tz_offset = round(lng / 15)  # rough solar timezone when unknown
    tz = timezone(timedelta(hours=tz_offset))
    when_local = when.replace(tzinfo=tz) if when else datetime.now(tz)
    sun_now = solar_position(lat, lng, when_local)
    events = sun_events(lat, lng, when_local.astimezone(timezone.utc))

    def local(dt):
        return dt.astimezone(tz).strftime('%H:%M') if dt else None

    report = {
        'query': text,
        'lat': lat, 'lng': lng,
        'candidates': candidates,
        'address': None, 'address_error': None,
        'pois': None, 'pois_error': None,
        'fires': None,
        'sun': {
            'when': when_local.strftime('%Y-%m-%d %H:%M'), 'tz_offset': tz_offset,
            **sun_now, 'shadow_ratio': shadow_ratio(sun_now['elevation']),
            'shadow_azimuth': round((sun_now['azimuth'] + 180) % 360, 1) if sun_now['elevation'] > 0 else None,
            'sunrise': local(events['sunrise']), 'sunset': local(events['sunset']),
            'solar_noon': local(events['solar_noon']),
            'table': sun_table(lat, lng, when_local, tz_offset),
        },
        'links': [{'label': lbl, 'url': url} for lbl, url in map_links(lat, lng)],
    }
    try:
        report['address'] = reverse_geocode(lat, lng)
    except Exception as e:
        report['address_error'] = str(e)[:200]
    if with_pois:
        try:
            report['pois'] = nearby_pois(lat, lng, radius)
        except Exception as e:
            report['pois_error'] = str(e)[:200]
    if with_fires:
        try:
            report['fires'] = firms_hotspots(lat, lng)
        except Exception as e:
            report['fires'] = {'status': 'error', 'message': str(e)[:200]}
    return report
