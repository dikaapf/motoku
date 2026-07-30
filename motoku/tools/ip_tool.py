import requests


def track(ip):
    resp = requests.get(f"http://ipwho.is/{ip}", timeout=10)
    data = resp.json()
    if not data.get('success', True):
        raise ValueError(data.get('message', 'IP tidak valid'))

    maps_url = f"https://www.google.com/maps/@{data['latitude']},{data['longitude']},8z"
    return {
        'ip': ip,
        'type': data.get('type', 'N/A'),
        'country': data.get('country', 'N/A'),
        'country_code': data.get('country_code', 'N/A'),
        'city': data.get('city', 'N/A'),
        'continent': data.get('continent', 'N/A'),
        'region': data.get('region', 'N/A'),
        'latitude': data.get('latitude', 'N/A'),
        'longitude': data.get('longitude', 'N/A'),
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
    resp = requests.get('https://api.ipify.org', timeout=5)
    return resp.text
