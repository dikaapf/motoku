import hmac
import secrets
import uuid
from datetime import datetime
from urllib.parse import quote

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import db
import rate_limit
from config import Config
from services import cache as result_cache
from services import detect as input_detect
from services import providers as provider_registry
from services.providers import registry as _provider_declarations  # noqa: F401
from tools import (
    cctv_tool,
    deep_username,
    dns_security,
    dns_tool,
    domain_tool,
    dorks_tool,
    email_tool,
    flight_tool,
    ip_tool,
    phone_tool,
    portscan_tool,
    search_tool,
    subdomain_tool,
    tech_tool,
    web_security,
    wmn_tool,
)

app = Flask(__name__)
app.config.from_object(Config)
db.configure(app.config['DB_PATH'])

# Endpoints that cannot carry a session CSRF token (public tracking beacon).
CSRF_EXEMPT_ENDPOINTS = {'receive_location'}


def generate_csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token


app.jinja_env.globals['csrf_token'] = generate_csrf_token


def _check_basic_auth():
    """Return a 401 response when Basic auth is enabled and missing/invalid."""
    expected_user = app.config.get('AUTH_USER')
    expected_password = app.config.get('AUTH_PASSWORD')
    if not expected_user or not expected_password:
        return None

    auth = request.authorization
    valid = (
        auth is not None
        and hmac.compare_digest(auth.username or '', expected_user)
        and hmac.compare_digest(auth.password or '', expected_password)
    )
    if valid:
        return None
    return Response(
        'Authentication required',
        401,
        {'WWW-Authenticate': 'Basic realm="Motoku OSINT"'},
    )


@app.before_request
def enforce_rate_limit():
    if not app.config.get('RATE_LIMIT_ENABLED', True):
        return None
    if request.path.startswith('/static/'):
        return None

    client = request.remote_addr or 'unknown'
    allowed, retry_after = rate_limit.check(
        client,
        app.config['RATE_LIMIT_REQUESTS'],
        app.config['RATE_LIMIT_WINDOW'],
    )
    if allowed:
        return None

    response = jsonify({'error': 'rate limit exceeded', 'retry_after': retry_after})
    response.status_code = 429
    response.headers['Retry-After'] = str(retry_after)
    return response


@app.before_request
def require_auth():
    if request.path.startswith('/static/'):
        return None
    return _check_basic_auth()


@app.before_request
def csrf_protect():
    if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return None
    if not app.config.get('CSRF_ENABLED', True):
        return None
    if request.endpoint in CSRF_EXEMPT_ENDPOINTS:
        return None

    expected = session.get('_csrf_token')
    supplied = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        abort(400, description='CSRF token tidak valid')
    return None


@app.after_request
def set_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'geolocation=(self)')
    return response


@app.route('/')
def index():
    return render_template('index.html')


# ── UNIFIED SEARCH ──
@app.route('/search')
def unified_search():
    query = request.args.get('q', '').strip()
    if not query:
        return redirect(url_for('index'))
    routing = input_detect.routes_for(query)
    if request.args.get('go') == '1' and routing['tools']:
        primary = routing['tools'][0]
        return redirect(url_for(primary['endpoint'], q=primary['value'], auto=1))
    return render_template('search.html', routing=routing)


@app.route('/api/detect')
def api_detect():
    return jsonify(input_detect.routes_for(request.args.get('q', '')))


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


# ── USERNAME (WhatsMyName) ──
@app.route('/username', methods=['GET', 'POST'])
def username():
    data = error = None
    selected = []
    include_nsfw = False
    if request.method == 'POST':
        u = request.form.get('username', '').strip()
        selected = [c for c in request.form.getlist('categories') if c]
        include_nsfw = request.form.get('nsfw') == '1'
        if not u:
            error = 'Masukkan username'
        else:
            try:
                data = wmn_tool.search(u, categories=selected or None, include_nsfw=include_nsfw)
            except Exception as e:
                error = f'Gagal: {e}'
    return render_template('username.html', data=data, error=error,
                           dataset=wmn_tool.dataset_info(), selected=selected,
                           include_nsfw=include_nsfw, nsfw_category=wmn_tool.NSFW_CATEGORY)


@app.route('/username/update-dataset', methods=['POST'])
def username_update_dataset():
    try:
        total = wmn_tool.update_dataset()
        return jsonify({'success': True, 'total': total})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 502


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

                for entry in sherlock_data.get('found', [])[:12]:
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


# ── EMAIL INTELLIGENCE ──
@app.route('/email', methods=['GET', 'POST'])
def email():
    report = error = None
    smtp_check = False
    if request.method == 'POST':
        addr = request.form.get('email', '').strip()
        smtp_check = request.form.get('smtp') == '1'
        if not addr:
            error = 'Masukkan alamat email'
        else:
            try:
                report = email_tool.investigate(addr, smtp_check=smtp_check)
            except Exception as e:
                error = str(e)
    return render_template('email.html', report=report, error=error, smtp_check=smtp_check,
                           hibp_configured=provider_registry.get('hibp').configured)


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


# ── DNS SECURITY ──
@app.route('/dns-security', methods=['GET', 'POST'])
def dns_security_page():
    report = error = None
    if request.method == 'POST':
        domain_val = request.form.get('domain', '').strip()
        if not domain_val:
            error = 'Masukkan domain'
        else:
            try:
                report = dns_security.analyse(domain_val)
            except Exception as e:
                error = str(e)
    return render_template('dns_security.html', report=report, error=error)


# ── WEB SECURITY (headers + TLS) ──
@app.route('/web-security', methods=['GET', 'POST'])
def web_security_page():
    report = error = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            error = 'Masukkan URL'
        else:
            try:
                report = web_security.analyse(url)
            except Exception as e:
                error = str(e)
    return render_template('web_security.html', report=report, error=error)


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
                search_results = search_tool.wikipedia_results(name_val)
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
        db.create_tracking(tracking_id, label)
        return redirect(url_for('location_tracker_results', tracking_id=tracking_id))

    return render_template('location_tracker.html', tracks=db.list_tracking(),
                           base_url=request.host_url.rstrip('/'))


@app.route('/track/<tracking_id>')
def track_page(tracking_id):
    if db.get_tracking(tracking_id) is None:
        abort(404)
    return render_template('track_page.html', tracking_id=tracking_id)


@app.route('/api/location/<tracking_id>', methods=['POST'])
def receive_location(tracking_id):
    if db.get_tracking(tracking_id) is None:
        return jsonify({'error': 'not found'}), 404

    body = request.get_json(silent=True) or {}
    location = {
        'lat': body.get('lat'),
        'lng': body.get('lng'),
        'accuracy': body.get('accuracy'),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', ''),
    }
    db.update_tracking_location(tracking_id, location, body.get('device_info'))
    return jsonify({'ok': True})


@app.route('/location-tracker/<tracking_id>/results')
def location_tracker_results(tracking_id):
    track = db.get_tracking(tracking_id)
    if track is None:
        abort(404)
    base_url = request.host_url.rstrip('/')
    encoded_url = quote(f'{base_url}/track/{tracking_id}')
    return render_template('location_tracker_results.html',
                           track=track, tracking_id=tracking_id,
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


@app.route('/cctv/sync', methods=['POST'])
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


@app.route('/status')
def status():
    safe_config = {
        'debug': app.config['DEBUG'],
        'auth_enabled': bool(app.config['AUTH_USER']),
        'csrf_enabled': app.config['CSRF_ENABLED'],
        'rate_limit_enabled': app.config['RATE_LIMIT_ENABLED'],
        'rate_limit_requests': app.config['RATE_LIMIT_REQUESTS'],
        'rate_limit_window': app.config['RATE_LIMIT_WINDOW'],
        'db_path': db.get_db_path(),
    }
    usage = {row['provider']: row for row in db.provider_usage()}
    registered = []
    for provider in provider_registry.all_providers():
        item = provider.status()
        item['usage'] = usage.pop(provider.name, None)
        registered.append(item)
    return render_template(
        'status.html',
        config=safe_config,
        db_stats=db.stats(),
        providers=list(usage.values()),
        registered=registered,
        cache_info=result_cache.info(),
        wmn=wmn_tool.dataset_info(),
        disposable_total=len(email_tool.disposable_domains()),
        rate_stats=rate_limit.stats(),
    )


if __name__ == '__main__':
    app.run(
        host=app.config['HOST'],
        port=app.config['PORT'],
        debug=app.config['DEBUG'],
    )
