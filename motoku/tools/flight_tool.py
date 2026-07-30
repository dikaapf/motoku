import time
import requests

OPENSKY_API = 'https://opensky-network.org/api/states/all'
_cache = {'data': None, 'time': 0, 'ttl': 10}

STATE_KEYS = [
    'icao24', 'callsign', 'origin_country', 'time_position',
    'last_contact', 'lon', 'lat', 'baro_altitude', 'on_ground',
    'velocity', 'heading', 'vertical_rate', 'sensors',
    'geo_altitude', 'squawk', 'spi', 'position_source',
]


def _fetch():
    now = time.time()
    if _cache['data'] and now - _cache['time'] < _cache['ttl']:
        return _cache['data']
    try:
        resp = requests.get(OPENSKY_API, timeout=15)
        resp.raise_for_status()
        raw = resp.json()
        flights = []
        for s in raw.get('states', []):
            f = dict(zip(STATE_KEYS, s))
            f['callsign'] = (f['callsign'] or '').strip()
            f['lon'] = float(f['lon']) if f['lon'] is not None else None
            f['lat'] = float(f['lat']) if f['lat'] is not None else None
            f['baro_altitude'] = float(f['baro_altitude']) if f['baro_altitude'] is not None else None
            f['geo_altitude'] = float(f['geo_altitude']) if f['geo_altitude'] is not None else None
            f['velocity'] = float(f['velocity']) if f['velocity'] is not None else None
            f['heading'] = float(f['heading']) if f['heading'] is not None else None
            f['vertical_rate'] = float(f['vertical_rate']) if f['vertical_rate'] is not None else None
            flights.append(f)
        result = {'time': raw.get('time'), 'flights': flights}
        _cache['data'] = result
        _cache['time'] = now
        return result
    except Exception as e:
        if _cache['data']:
            return _cache['data']
        raise RuntimeError(f'Gagal mengambil data penerbangan: {e}')


def get_flights():
    data = _fetch()
    return data['flights']


def get_flights_in_bounds(lat_min, lon_min, lat_max, lon_max):
    flights = get_flights()
    return [
        f for f in flights
        if f['lat'] is not None and f['lon'] is not None
        and lat_min <= f['lat'] <= lat_max
        and lon_min <= f['lon'] <= lon_max
    ]


def get_stats(flights=None):
    if flights is None:
        flights = get_flights()
    total = len(flights)
    on_ground = sum(1 for f in flights if f['on_ground'])
    airborne = total - on_ground
    countries = {}
    for f in flights:
        c = f['origin_country'] or 'Unknown'
        countries[c] = countries.get(c, 0) + 1
    top_countries = sorted(countries.items(), key=lambda x: -x[1])[:10]
    return {
        'total': total,
        'airborne': airborne,
        'on_ground': on_ground,
        'top_countries': top_countries,
    }
