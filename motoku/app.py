from flask import Flask, render_template, request, jsonify

from tools import phone_tool, ip_tool, username_tool, email_tool
from tools import domain_tool, dns_tool, portscan_tool, tech_tool, dorks_tool, deep_username

app = Flask(__name__)


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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
