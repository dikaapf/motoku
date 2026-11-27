"""Tests for S6: i18n, catalog/palette, performance, observability, onboarding."""

import gzip
import json
import os
import subprocess
import sys

import pytest

from app import app as flask_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── 6.1 i18n ──


def test_default_language_is_indonesian(client):
    body = client.get('/', headers={'Accept-Language': 'id'}).data.decode()
    assert 'lang="id"' in body and 'Alur kerja' in body


def test_english_via_query_sets_cookie(client):
    resp = client.get('/?lang=en')
    body = resp.data.decode()
    assert 'lang="en"' in body
    assert 'Workflow' in body and 'People &amp; identity' in body
    assert 'motoku_lang=en' in resp.headers.get('Set-Cookie', '')
    assert 'Workflow' in client.get('/').data.decode()  # cookie persists


def test_accept_language_and_switch_route(client):
    assert 'lang="en"' in client.get('/', headers={'Accept-Language': 'en-US,en;q=0.9'}).data.decode()
    resp = client.get('/lang/id', headers={'Referer': 'http://localhost/cases'})
    assert resp.status_code == 302 and resp.headers['Location'].endswith('/cases')
    assert 'motoku_lang=id' in resp.headers['Set-Cookie']
    assert client.get('/lang/xx').status_code == 302


def test_translation_catalogue_is_complete():
    proc = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'i18n_check.py')],
                          capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 0, proc.stdout


def test_gettext_formatting_and_fallback():
    from flask import g

    from services import i18n

    with flask_app.test_request_context('/'):
        g.lang = 'en'
        assert i18n.gettext('(+{n} lainnya)', n=3) == '(+3 more)'
        assert i18n.gettext('String tanpa terjemahan') == 'String tanpa terjemahan'
        g.lang = 'id'
        assert i18n.gettext('Beranda') == 'Beranda'


@pytest.mark.parametrize('path', ['/', '/search?q=example.com', '/cases', '/recon', '/welcome', '/intel'])
def test_pages_render_in_english(client, path):
    resp = client.get(path + ('&' if '?' in path else '?') + 'lang=en')
    assert resp.status_code == 200


# ── 6.2 catalog, palette, menu ──

def test_catalog_endpoints_all_exist():
    from services import catalog

    endpoints = {r.endpoint for r in flask_app.url_map.iter_rules()}
    for t in catalog.tools():
        assert t['endpoint'] in endpoints, t['endpoint']
    assert catalog.count() >= 27


def test_menu_and_palette_generated_from_catalog(client):
    from services import catalog

    body = client.get('/phone').data.decode()
    assert 'id="palette-modal"' in body
    assert body.count('class="dropdown-item rounded') == sum(1 for t in catalog.tools() if t['category'] != 'workflow')
    palette = body.split('palette: [', 1)[1].split('],\n', 1)[0]
    assert '"Threat Intel"' in palette and '/intel' in palette


def test_home_cards_cover_tools(client):
    body = client.get('/').data.decode()
    for endpoint in ('/geo', '/cve', '/recon', '/cases', '/social'):
        assert f'href="{endpoint}"' in body


# ── 6.3 performance ──

def test_connection_is_pooled_per_thread():
    import threading

    import db

    a = db.get_connection()
    assert db.get_connection() is a
    other = []
    t = threading.Thread(target=lambda: other.append(db.get_connection()))
    t.start()
    t.join()
    assert other[0] is not a


def test_connection_rolls_back_on_error():
    import db

    with pytest.raises(RuntimeError):
        with db.connection() as conn:
            conn.execute("INSERT INTO cases (id, title, status, created_at, updated_at) VALUES ('rb', 't', 'open', 'x', 'x')")
            raise RuntimeError('boom')
    with db.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM cases WHERE id = 'rb'").fetchone()[0] == 0


def test_hot_query_indexes_exist():
    import db

    with db.connection() as conn:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
        plan = ' '.join(str(tuple(r)) for r in conn.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM findings WHERE case_id = 'x' AND status IN ('open', 'confirmed')"))
    for idx in ('idx_findings_case_status', 'idx_watch_due', 'idx_jobs_status', 'idx_alerts_case'):
        assert idx in names
    assert 'idx_findings_case_status' in plan


def test_pragmas_applied():
    import db

    conn = db.get_connection()
    assert conn.execute('PRAGMA journal_mode').fetchone()[0] == 'wal'
    assert conn.execute('PRAGMA foreign_keys').fetchone()[0] == 1


def test_gzip_for_large_responses(client):
    resp = client.get('/', headers={'Accept-Encoding': 'gzip'})
    assert resp.headers.get('Content-Encoding') == 'gzip'
    assert b'Motoku' in gzip.decompress(resp.data)
    plain = client.get('/')
    assert 'Content-Encoding' not in plain.headers


def test_sse_not_compressed(client):
    from services import jobs

    @jobs.handler('unit-s6')
    def j(ctx):
        return 1

    jid = jobs.enqueue('unit-s6', 'x')
    resp = client.get(f'/api/jobs/{jid}/events', headers={'Accept-Encoding': 'gzip'})
    assert resp.mimetype == 'text/event-stream'
    assert 'Content-Encoding' not in resp.headers


def test_cache_warmup_runs_offline(monkeypatch):
    from services import observability

    monkeypatch.setenv('MOTOKU_WARMUP_NETWORK', '0')
    observability.warm_up(background=False)


# ── 6.4 logging & monitoring ──

def test_health_endpoints(client):
    assert client.get('/healthz').get_json()['status'] == 'ok'
    ready = client.get('/readyz')
    assert ready.status_code == 200 and ready.get_json()['checks']['db'] == 'ok'


def test_request_id_header(client):
    assert len(client.get('/healthz').headers['X-Request-ID']) == 16
    assert client.get('/healthz', headers={'X-Request-ID': 'abc'}).headers['X-Request-ID'] == 'abc'


def test_metrics_exposition(client):
    from services import casedb

    casedb.create_case('metrics')
    client.get('/')
    text = client.get('/metrics').data.decode()
    assert '# TYPE motoku_http_requests_total counter' in text
    assert 'motoku_http_requests_total{method="GET",endpoint="index",status="200"}' in text
    assert 'motoku_http_request_duration_seconds_bucket{endpoint="index",le="+Inf"}' in text
    assert 'motoku_cases{status="open"} 1' in text
    assert 'motoku_cache_keys' in text


def test_metrics_token(client, monkeypatch):
    monkeypatch.setenv('MOTOKU_METRICS_TOKEN', 's3cret')
    assert client.get('/metrics').status_code == 401
    assert client.get('/metrics', headers={'Authorization': 'Bearer s3cret'}).status_code == 200
    assert client.get('/metrics?token=s3cret').status_code == 200


def test_probes_bypass_rate_limit(client):
    import rate_limit

    flask_app.config.update(RATE_LIMIT_ENABLED=True, RATE_LIMIT_REQUESTS=1, RATE_LIMIT_WINDOW=60)
    try:
        for _ in range(5):
            assert client.get('/healthz').status_code == 200
    finally:
        flask_app.config.update(RATE_LIMIT_ENABLED=False, RATE_LIMIT_REQUESTS=120)
        rate_limit.reset()


def test_json_log_formatter():
    import logging

    from services.observability import JsonFormatter

    record = logging.LogRecord('motoku', logging.INFO, __file__, 1, 'GET / 200', None, None)
    record.request_id = 'r1'
    record.status = 200
    data = json.loads(JsonFormatter().format(record))
    assert data['msg'] == 'GET / 200' and data['request_id'] == 'r1' and data['status'] == 200


def test_sentry_optional_without_package(monkeypatch):
    from services import observability

    monkeypatch.setenv('MOTOKU_SENTRY_DSN', 'https://key@example.invalid/1')
    import builtins
    real = builtins.__import__

    def fake(name, *a, **k):
        if name.startswith('sentry_sdk'):
            raise ImportError
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, '__import__', fake)
    assert observability.setup_sentry(flask_app) is False


# ── 6.5 onboarding & docs ──

def test_welcome_checklist(client):
    body = client.get('/welcome').data.decode()
    assert 'SECRET_KEY' in body and 'nmap' in body
    assert 'Mulai dalam 4 langkah' in body


def test_banner_warns_about_default_secret(client):
    flask_app.config['SECRET_KEY'] = 'dev-only-change-me'
    assert 'SECRET_KEY masih default' in client.get('/phone').data.decode()
    flask_app.config['SECRET_KEY'] = 'x' * 40
    try:
        assert 'SECRET_KEY masih default' not in client.get('/phone').data.decode()
    finally:
        flask_app.config['SECRET_KEY'] = 'dev-only-change-me'


@pytest.mark.parametrize('doc', ['README.md', 'USER_GUIDE.md', 'DEPLOYMENT.md', 'ARCHITECTURE.md', 'API.md',
                                 'DEVELOPMENT.md'])
def test_docs_exist(doc):
    path = os.path.join(os.path.dirname(ROOT), 'docs', doc)
    assert os.path.exists(path) and os.path.getsize(path) > 500


def test_stale_jobs_are_recovered():
    import db
    from services import jobs

    db.create_job('stale1', 'recon', 'x', {})
    db.update_job('stale1', status='running', started_at='2020-01-01 00:00:00')
    db.create_job('fresh1', 'recon', 'y', {})
    db.update_job('fresh1', status='running', started_at=db.now())
    assert jobs.recover_stale() == 1
    assert jobs.get('stale1')['status'] == 'failed'
    assert jobs.get('fresh1')['status'] == 'running'
