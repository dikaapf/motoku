import requests

from db import provider_call

IPWHOIS_URL = 'https://ipwho.is/{ip}'
IPIFY_URL = 'https://api.ipify.org'
TIMEOUT = 10


def track(ip):
    with provider_call('ipwho.is'):
        resp = requests.get(IPWHOIS_URL.format(ip=ip), timeout=TIMEOUT)
        resp.raise_for_status()
    data = resp.json()
    if not data.get('success', True):
        raise ValueError(data.get('message', 'IP tidak valid'))

    latitude = data.get('latitude')
    longitude = data.get('longitude')
    if latitude is not None and longitude is not None:
        maps_url = f"https://www.google.com/maps/@{latitude},{longitude},8z"
    else:
        maps_url = ''

    return {
        'ip': ip,
        'type': data.get('type', 'N/A'),
        'country': data.get('country', 'N/A'),
        'country_code': data.get('country_code', 'N/A'),
        'city': data.get('city', 'N/A'),
        'continent': data.get('continent', 'N/A'),
        'region': data.get('region', 'N/A'),
        'latitude': latitude if latitude is not None else 'N/A',
        'longitude': longitude if longitude is not None else 'N/A',
        'maps_url': maps_url,
        'postal': data.get('postal', 'N/A'),
        'calling_code': data.get('calling_code', 'N/A'),
        'capital': data.get('capital', 'N/A'),
        'flag': data.get('flag', {}).get('emoji', ''),
        'asn': data.get('connection', {}).get('asn', 'N/A'),
        'org': data.get('connection', {}).get('org', 'N/A'),
        'isp': data.get('connection', {}).get('isp', 'N/A'),
        'timezone_id': data.get('timezone', {}).get('id', 'N/A'),
        'current_time': data.get('timezone', {}).get('current_time', 'N/A'),
    }


def my_ip():
    with provider_call('ipify.org'):
        resp = requests.get(IPIFY_URL, timeout=5)
        resp.raise_for_status()
    return resp.text.strip()
