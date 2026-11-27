"""Logging, metrics, health checks, response compression and optional Sentry.

* Structured request logging (text or JSON via ``MOTOKU_LOG_FORMAT=json``) with
  a request id echoed in ``X-Request-ID``.
* ``/metrics`` in Prometheus text format: per-process HTTP counters/latency
  histogram plus DB-derived gauges (jobs, cases, alerts, provider usage) that
  are correct across gunicorn workers. Protect with ``MOTOKU_METRICS_TOKEN``.
* ``/healthz`` (liveness) and ``/readyz`` (DB + cache).
* gzip for large text/JSON responses.
* Sentry when ``MOTOKU_SENTRY_DSN`` is set and ``sentry-sdk`` is installed.
"""

import gzip
import json
import logging
import os
import sys
import threading
import time
import uuid
from collections import defaultdict

from flask import Response, g, jsonify, request

log = logging.getLogger('motoku')
BUCKETS = (0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60)
_lock = threading.Lock()
_requests = defaultdict(int)            # (method, endpoint, status) -> count
_latency = defaultdict(lambda: [0] * (len(BUCKETS) + 1))  # endpoint -> bucket counts
_latency_sum = defaultdict(float)
_started = time.time()
COMPRESSIBLE = ('text/', 'application/json', 'application/javascript', 'image/svg+xml', 'text/markdown')


class JsonFormatter(logging.Formatter):
    def format(self, record):
        data = {'ts': self.formatTime(record, '%Y-%m-%dT%H:%M:%S'), 'level': record.levelname,
                'logger': record.name, 'msg': record.getMessage()}
        for key in ('request_id', 'method', 'path', 'status', 'duration_ms', 'remote', 'endpoint'):
            if hasattr(record, key):
                data[key] = getattr(record, key)
        if record.exc_info:
            data['exc'] = self.formatException(record.exc_info)
        return json.dumps(data, ensure_ascii=False)


def setup_logging():
    level = os.environ.get('MOTOKU_LOG_LEVEL', 'INFO').upper()
    handler = logging.StreamHandler(sys.stdout)
    if os.environ.get('MOTOKU_LOG_FORMAT', 'text').lower() == 'json':
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s'))
    root = logging.getLogger('motoku')
    if not root.handlers:
        root.addHandler(handler)
    root.setLevel(level)
    root.propagate = False


def setup_sentry(app):
    dsn = os.environ.get('MOTOKU_SENTRY_DSN', '').strip()
    if not dsn:
        return False
    try:
        import sentry_sdk
        from sentry_sdk.integrations.flask import FlaskIntegration
    except ImportError:
        log.warning('MOTOKU_SENTRY_DSN diset tetapi sentry-sdk belum terpasang (pip install sentry-sdk)')
        return False
    sentry_sdk.init(dsn=dsn, integrations=[FlaskIntegration()], send_default_pii=False,
                    traces_sample_rate=float(os.environ.get('MOTOKU_SENTRY_TRACES', '0')),
                    environment=os.environ.get('MOTOKU_ENV', 'production'))
    app.config['SENTRY_ENABLED'] = True
    return True


def _endpoint_label():
    return request.endpoint or ('static' if request.path.startswith('/static/') else 'unknown')


def init_app(app):
    setup_logging()
    setup_sentry(app)

    @app.before_request
    def _start_timer():
        g.request_started = time.perf_counter()
        g.request_id = request.headers.get('X-Request-ID') or uuid.uuid4().hex[:16]

    @app.after_request
    def _finish(response):
        started = getattr(g, 'request_started', None)
        if started is None:
            return response
        duration = time.perf_counter() - started
        endpoint = _endpoint_label()
        with _lock:
            _requests[(request.method, endpoint, response.status_code)] += 1
            idx = next((i for i, b in enumerate(BUCKETS) if duration <= b), len(BUCKETS))
            _latency[endpoint][idx] += 1
            _latency_sum[endpoint] += duration
        response.headers.setdefault('X-Request-ID', g.request_id)
        if endpoint != 'static' and not request.path.startswith(('/metrics', '/healthz')):
            log.info('%s %s %s %.0fms', request.method, request.path, response.status_code, duration * 1000,
                     extra={'request_id': g.request_id, 'method': request.method, 'path': request.path,
                            'status': response.status_code, 'duration_ms': round(duration * 1000, 1),
                            'remote': request.remote_addr, 'endpoint': endpoint})
        return _compress(response)

    @app.route('/healthz')
    def healthz():
        return jsonify({'status': 'ok', 'uptime_s': int(time.time() - _started)})

    @app.route('/readyz')
    def readyz():
        import db
        from services import cache
        checks = {}
        try:
            with db.connection() as conn:
                conn.execute('SELECT 1').fetchone()
            checks['db'] = 'ok'
        except Exception as e:
            checks['db'] = f'error: {e}'
        info = cache.info()
        checks['cache'] = 'ok' if info.get('backend') in ('memory', 'redis') else f'error: {info}'
        ok = all(v == 'ok' for v in checks.values())
        return jsonify({'status': 'ok' if ok else 'degraded', 'checks': checks}), 200 if ok else 503

    @app.route('/metrics')
    def metrics():
        token = os.environ.get('MOTOKU_METRICS_TOKEN', '').strip()
        if token and request.headers.get('Authorization', '') != f'Bearer {token}' \
                and request.args.get('token') != token:
            return Response('unauthorized\n', 401)
        return Response(render_metrics(), mimetype='text/plain; version=0.0.4')


def _compress(response):
    if response.direct_passthrough or response.status_code < 200 or response.status_code >= 300:
        return response
    if 'gzip' not in request.headers.get('Accept-Encoding', '') or response.headers.get('Content-Encoding'):
        return response
    if not (response.mimetype or '').startswith(COMPRESSIBLE) or response.mimetype == 'text/event-stream':
        return response
    data = response.get_data()
    if len(data) < 1024:
        return response
    response.set_data(gzip.compress(data, compresslevel=6))
    response.headers['Content-Encoding'] = 'gzip'
    response.headers['Content-Length'] = str(len(response.get_data()))
    response.headers.add('Vary', 'Accept-Encoding')
    return response


def _esc(value):
    return str(value).replace('\\', '\\\\').replace('"', '\\"').replace('\n', ' ')


def render_metrics():
    import db
    from services import cache
    lines = []

    def metric(name, kind, help_text, samples):
        lines.append(f'# HELP {name} {help_text}')
        lines.append(f'# TYPE {name} {kind}')
        for labels, value in samples:
            label_txt = ','.join(f'{k}="{_esc(v)}"' for k, v in labels.items())
            lines.append(f'{name}{{{label_txt}}} {value}' if label_txt else f'{name} {value}')

    metric('motoku_info', 'gauge', 'Build info', [({'version': '1.6', 'pid': os.getpid()}, 1)])
    metric('motoku_process_uptime_seconds', 'gauge', 'Process uptime', [({}, round(time.time() - _started, 1))])
    with _lock:
        req = [({'method': m, 'endpoint': e, 'status': s}, n) for (m, e, s), n in sorted(_requests.items())]
        hist = []
        for endpoint, counts in sorted(_latency.items()):
            cumulative = 0
            for bound, n in zip(list(BUCKETS) + ['+Inf'], counts):
                cumulative += n
                hist.append(({'endpoint': endpoint, 'le': bound}, cumulative))
        sums = [({'endpoint': e}, round(v, 4)) for e, v in sorted(_latency_sum.items())]
        totals = [({'endpoint': e}, sum(c)) for e, c in sorted(_latency.items())]
    metric('motoku_http_requests_total', 'counter', 'HTTP requests (per process)', req)
    lines.append('# HELP motoku_http_request_duration_seconds Request latency (per process)')
    lines.append('# TYPE motoku_http_request_duration_seconds histogram')
    for labels, v in hist:
        lines.append(f'motoku_http_request_duration_seconds_bucket{{endpoint="{labels["endpoint"]}",le="{labels["le"]}"}} {v}')
    for labels, v in sums:
        lines.append(f'motoku_http_request_duration_seconds_sum{{endpoint="{labels["endpoint"]}"}} {v}')
    for labels, v in totals:
        lines.append(f'motoku_http_request_duration_seconds_count{{endpoint="{labels["endpoint"]}"}} {v}')

    try:
        with db.connection() as conn:
            jobs = conn.execute('SELECT kind, status, COUNT(*) AS n FROM jobs GROUP BY kind, status').fetchall()
            cases = conn.execute('SELECT status, COUNT(*) AS n FROM cases GROUP BY status').fetchall()
            ents = conn.execute('SELECT COUNT(*) FROM entities').fetchone()[0]
            alerts = conn.execute('SELECT severity, acknowledged, COUNT(*) AS n FROM alerts GROUP BY severity, acknowledged').fetchall()
            watches = conn.execute('SELECT enabled, COUNT(*) AS n FROM watchlist GROUP BY enabled').fetchall()
            providers = conn.execute('SELECT provider, calls, errors, cache_hits FROM provider_usage').fetchall()
            running_age = conn.execute("SELECT MIN(started_at) FROM jobs WHERE status = 'running'").fetchone()[0]
    except Exception as e:
        lines.append(f'# db error: {_esc(e)}')
        return '\n'.join(lines) + '\n'
    metric('motoku_jobs', 'gauge', 'Jobs by kind and status', [({'kind': r['kind'], 'status': r['status']}, r['n']) for r in jobs])
    metric('motoku_cases', 'gauge', 'Cases by status', [({'status': r['status']}, r['n']) for r in cases])
    metric('motoku_entities', 'gauge', 'Entities across all cases', [({}, ents)])
    metric('motoku_alerts', 'gauge', 'Watchlist alerts', [({'severity': r['severity'], 'acknowledged': r['acknowledged']}, r['n']) for r in alerts])
    metric('motoku_watchlist_items', 'gauge', 'Watchlist items', [({'enabled': r['enabled']}, r['n']) for r in watches])
    metric('motoku_provider_calls_total', 'counter', 'Outbound provider calls', [({'provider': r['provider']}, r['calls']) for r in providers])
    metric('motoku_provider_errors_total', 'counter', 'Outbound provider errors', [({'provider': r['provider']}, r['errors']) for r in providers])
    metric('motoku_provider_cache_hits_total', 'counter', 'Provider cache hits', [({'provider': r['provider']}, r['cache_hits']) for r in providers])
    if running_age:
        from datetime import datetime
        age = (datetime.now() - datetime.strptime(running_age, '%Y-%m-%d %H:%M:%S')).total_seconds()
        metric('motoku_oldest_running_job_seconds', 'gauge', 'Age of the oldest running job', [({}, int(age))])
    info = cache.info()
    metric('motoku_cache_keys', 'gauge', 'Keys in the result cache', [({'backend': info.get('backend')}, info.get('keys') or 0)])
    return '\n'.join(lines) + '\n'


# ── cache warm-up ──
def warm_up(background=True):
    """Pre-load local datasets (and the CISA KEV catalogue) so first requests are fast."""
    def run():
        started = time.perf_counter()
        done = []
        try:
            from tools import email_tool, wmn_tool
            wmn_tool.load_dataset()
            done.append('whatsmyname')
            email_tool.disposable_domains()
            done.append('disposable')
        except Exception as e:
            log.warning('warm-up dataset gagal: %s', e)
        if os.environ.get('MOTOKU_WARMUP_NETWORK', '1') == '1':
            try:
                from tools import cve_tool
                cve_tool.kev_catalog()
                done.append('cisa-kev')
            except Exception as e:
                log.info('warm-up KEV dilewati: %s', e)
        log.info('cache warm-up selesai (%s) dalam %.1fs', ', '.join(done), time.perf_counter() - started)
    if background:
        threading.Thread(target=run, name='motoku-warmup', daemon=True).start()
    else:
        run()
