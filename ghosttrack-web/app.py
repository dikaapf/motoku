import json
import requests
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

SOCIAL_MEDIA = [
    {"url": "https://www.facebook.com/{}", "name": "Facebook"},
    {"url": "https://www.twitter.com/{}", "name": "Twitter"},
    {"url": "https://www.instagram.com/{}", "name": "Instagram"},
    {"url": "https://www.linkedin.com/in/{}", "name": "LinkedIn"},
    {"url": "https://www.github.com/{}", "name": "GitHub"},
    {"url": "https://www.pinterest.com/{}", "name": "Pinterest"},
    {"url": "https://www.tumblr.com/{}", "name": "Tumblr"},
    {"url": "https://www.youtube.com/{}", "name": "Youtube"},
    {"url": "https://soundcloud.com/{}", "name": "SoundCloud"},
    {"url": "https://www.snapchat.com/add/{}", "name": "Snapchat"},
    {"url": "https://www.tiktok.com/@{}", "name": "TikTok"},
    {"url": "https://www.behance.net/{}", "name": "Behance"},
    {"url": "https://www.medium.com/@{}", "name": "Medium"},
    {"url": "https://www.quora.com/profile/{}", "name": "Quora"},
    {"url": "https://www.flickr.com/people/{}", "name": "Flickr"},
    {"url": "https://www.twitch.tv/{}", "name": "Twitch"},
    {"url": "https://www.dribbble.com/{}", "name": "Dribbble"},
    {"url": "https://www.producthunt.com/@{}", "name": "Product Hunt"},
    {"url": "https://www.telegram.me/{}", "name": "Telegram"},
    {"url": "https://www.weheartit.com/{}", "name": "We Heart It"},
]


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/phone', methods=['GET', 'POST'])
def phone():
    result = None
    error = None
    if request.method == 'POST':
        number = request.form.get('number', '').strip()
        if not number:
            error = 'Masukkan nomor telepon'
        else:
            try:
                default_region = "ID"
                parsed = phonenumbers.parse(number, default_region)
                region_code = phonenumbers.region_code_for_number(parsed)
                provider = carrier.name_for_number(parsed, "en")
                location = geocoder.description_for_number(parsed, "id")
                is_valid = phonenumbers.is_valid_number(parsed)
                is_possible = phonenumbers.is_possible_number(parsed)
                intl_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
                e164_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
                ntype = phonenumbers.number_type(parsed)
                tz = timezone.time_zones_for_number(parsed)
                tz_str = ', '.join(tz)

                type_label = {phonenumbers.PhoneNumberType.MOBILE: 'Mobile',
                              phonenumbers.PhoneNumberType.FIXED_LINE: 'Fixed Line',
                              phonenumbers.PhoneNumberType.VOIP: 'VoIP'}.get(ntype, 'Lainnya')

                result = {
                    'location': location or 'Tidak diketahui',
                    'region_code': region_code,
                    'timezone': tz_str,
                    'operator': provider or 'Tidak diketahui',
                    'valid': 'Ya' if is_valid else 'Tidak',
                    'possible': 'Ya' if is_possible else 'Tidak',
                    'international': intl_format,
                    'e164': e164_format,
                    'national': str(parsed.national_number),
                    'country_code': f'+{parsed.country_code}',
                    'type': type_label,
                }
            except Exception as e:
                error = f'Gagal memproses nomor: {str(e)}'
    return render_template('phone.html', result=result, error=error)


@app.route('/ip', methods=['GET', 'POST'])
def ip_track():
    result = None
    error = None
    if request.method == 'POST':
        ip = request.form.get('ip', '').strip()
        if not ip:
            error = 'Masukkan alamat IP'
        else:
            try:
                resp = requests.get(f"http://ipwho.is/{ip}", timeout=10)
                data = resp.json()
                if not data.get('success', True):
                    error = f"IP tidak valid: {data.get('message', 'Unknown error')}"
                else:
                    maps_url = f"https://www.google.com/maps/@{data['latitude']},{data['longitude']},8z"
                    result = {
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
            except requests.RequestException as e:
                error = f'Gagal menghubungi API: {str(e)}'
    return render_template('ip.html', result=result, error=error)


@app.route('/username', methods=['GET', 'POST'])
def username():
    results = None
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        if not username:
            error = 'Masukkan username'
        else:
            results = []
            for site in SOCIAL_MEDIA:
                url = site['url'].format(username)
                try:
                    resp = requests.get(url, timeout=5)
                    found = resp.status_code == 200
                except requests.RequestException:
                    found = False
                results.append({
                    'name': site['name'],
                    'url': url,
                    'found': found,
                })
    return render_template('username.html', results=results, error=error)


@app.route('/api/myip')
def my_ip():
    try:
        resp = requests.get('https://api.ipify.org', timeout=5)
        return jsonify({'ip': resp.text})
    except requests.RequestException:
        return jsonify({'ip': 'Tidak dapat memperoleh IP'})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
