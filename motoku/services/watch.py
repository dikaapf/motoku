"""Watchlist monitoring: periodic snapshots of a target, diffed against the
previous snapshot; changes become alerts delivered by webhook and/or email.

Check types per target type:
* domain   — dns (A/MX/NS/TXT), tls (issuer/expiry), subdomains (passive CT),
             intel (reputation verdict), typosquat (newly registered look-alikes)
* ip       — ports & CVEs (Shodan InternetDB), intel verdict
* email    — breaches (HIBP)
* username — social profiles
"""

import json
import os
import smtplib
import socket
import threading
import time
from datetime import datetime, timedelta
from email.message import EmailMessage

import requests

import db
from services import casedb

TARGET_TYPES = {
    'domain': ['dns', 'tls', 'subdomains', 'intel', 'typosquat'],
    'ip': ['ports', 'intel'],
    'email': ['breaches'],
    'username': ['social'],
}
DEFAULT_CHECKS = {'domain': ['dns', 'tls', 'subdomains', 'intel'], 'ip': ['ports', 'intel'],
                  'email': ['breaches'], 'username': ['social']}


def _load(raw, default=None):
    return json.loads(raw) if raw else default


def _row(r):
    d = dict(r)
    d['checks'] = _load(d.pop('checks_json'), [])
    d['notify'] = _load(d.pop('notify_json'), {})
    d['snapshot'] = _load(d.pop('snapshot_json'), None)
    return d


# ── CRUD ──
def add(target_type, target, checks=None, interval_min=1440, case_id=None, label=None, notify=None):
    if target_type not in TARGET_TYPES:
        raise ValueError('Tipe target tidak didukung')
    target = (target or '').strip().lower() if target_type != 'username' else (target or '').strip()
    if not target:
        raise ValueError('Target kosong')
    checks = [c for c in (checks or DEFAULT_CHECKS[target_type]) if c in TARGET_TYPES[target_type]]
    interval_min = max(15, min(int(interval_min), 60 * 24 * 30))
    with db.connection() as conn:
        cur = conn.execute(
            'INSERT INTO watchlist (case_id, type, target, label, checks_json, notify_json, interval_min, enabled,'
            ' next_run, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)',
            (case_id or None, target_type, target, label, json.dumps(checks), json.dumps(notify or {}),
             interval_min, casedb.now(), casedb.now()))
    if case_id:
        with db.connection() as conn:
            casedb._event(conn, case_id, 'watch', f'Watchlist ditambahkan: {target_type} {target}')
    return cur.lastrowid


def get(watch_id):
    with db.connection() as conn:
        r = conn.execute('SELECT * FROM watchlist WHERE id = ?', (watch_id,)).fetchone()
    return _row(r) if r else None


def list_all(case_id=None):
    sql, args = 'SELECT * FROM watchlist', []
    if case_id:
        sql += ' WHERE case_id = ?'
        args.append(case_id)
    with db.connection() as conn:
        return [_row(r) for r in conn.execute(sql + ' ORDER BY id DESC', args)]


def set_enabled(watch_id, enabled):
    with db.connection() as conn:
        conn.execute('UPDATE watchlist SET enabled = ? WHERE id = ?', (1 if enabled else 0, watch_id))


def delete(watch_id):
    with db.connection() as conn:
        conn.execute('DELETE FROM watchlist WHERE id = ?', (watch_id,))


def due(limit=20):
    with db.connection() as conn:
        rows = conn.execute('SELECT * FROM watchlist WHERE enabled = 1 AND (next_run IS NULL OR next_run <= ?)'
                            ' ORDER BY next_run LIMIT ?', (casedb.now(), limit)).fetchall()
    return [_row(r) for r in rows]


def list_alerts(limit=100, case_id=None, unacked=False):
    sql = 'SELECT a.*, w.target, w.type FROM alerts a LEFT JOIN watchlist w ON w.id = a.watch_id WHERE 1=1'
    args = []
    if case_id:
        sql += ' AND a.case_id = ?'
        args.append(case_id)
    if unacked:
        sql += ' AND a.acknowledged = 0'
    with db.connection() as conn:
        rows = conn.execute(sql + ' ORDER BY a.id DESC LIMIT ?', [*args, limit]).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d['data'] = _load(d.pop('data_json'), None)
        d['delivery'] = _load(d.pop('delivery_json'), {})
        out.append(d)
    return out


def acknowledge(alert_id):
    with db.connection() as conn:
        conn.execute('UPDATE alerts SET acknowledged = 1 WHERE id = ?', (alert_id,))


# ── checks (return JSON-serialisable snapshots) ──
def check_dns(target):
    from services import resolver
    return {t: sorted(resolver.resolve(target, t)) for t in ('A', 'MX', 'NS', 'TXT')}


def check_tls(target):
    from tools.web_security import tls_info
    try:
        c = tls_info(target)
    except ValueError as e:
        return {'error': str(e)[:120]}
    return {'issuer': (c.get('issuer') or {}).get('organizationName') or (c.get('issuer') or {}).get('commonName'),
            'serial': c.get('serial'), 'not_after': c.get('not_after'), 'days_left': c.get('days_left'),
            'verified': c.get('verified')}


def check_subdomains(target):
    from tools import subdomain_tool
    data = subdomain_tool.enumerate_subdomains(target, sources=['crt.sh', 'certspotter'], brute=False, resolve=False)
    return {'names': sorted(h['name'] for h in data['hosts'])}


def check_intel(target):
    from tools import threat_intel
    r = threat_intel.lookup(target, include_unconfigured=False)
    return {'verdict': r['summary']['verdict'],
            'flagged_by': sorted(x['source'] for x in r['results'] if x['verdict'] in ('malicious', 'suspicious'))}


def check_typosquat(target):
    from tools import typosquat
    r = typosquat.scan(target, max_candidates=600)
    return {'registered': sorted(t['ascii'] for t in r['registered'] if t['risk'] != 'low')}


def check_ports(target):
    from tools import threat_intel
    r = threat_intel.internetdb('ip', target)
    return {'ports': sorted(r['data'].get('ports', [])), 'vulns': sorted(r['data'].get('vulns', []))}


def check_breaches(target):
    from tools import email_tool
    r = email_tool.hibp(target)
    if r['status'] in ('no_key', 'error'):
        return {'error': r.get('message')}
    return {'breaches': sorted(b['name'] for b in r['breaches'])}


def check_social(target):
    from tools import social_tool
    r = social_tool.lookup(target)
    return {'profiles': sorted(p['url'] for x in r['results'] for p in x['profiles'])}


CHECKS = {'dns': check_dns, 'tls': check_tls, 'subdomains': check_subdomains, 'intel': check_intel,
          'typosquat': check_typosquat, 'ports': check_ports, 'breaches': check_breaches, 'social': check_social}


# ── diff → alerts ──
def _list_diff(old, new):
    old, new = set(old or []), set(new or [])
    return sorted(new - old), sorted(old - new)


def diff(check, old, new, target):
    """Return a list of (severity, title, detail) for meaningful changes."""
    if old is None or 'error' in (old or {}) or 'error' in (new or {}):
        return []
    alerts = []
    if check == 'dns':
        for rtype in new:
            added, removed = _list_diff(old.get(rtype), new.get(rtype))
            if added or removed:
                alerts.append(('medium' if rtype in ('NS', 'MX') else 'low', f'DNS {rtype} {target} berubah',
                               f'+ {", ".join(added) or "-"} / − {", ".join(removed) or "-"}'))
    elif check == 'tls':
        if old.get('serial') != new.get('serial'):
            sev = 'medium' if old.get('issuer') != new.get('issuer') else 'info'
            alerts.append((sev, f'Sertifikat TLS {target} diganti',
                           f'Issuer {old.get("issuer")} → {new.get("issuer")}, berlaku s/d {new.get("not_after")}'))
        if new.get('days_left') is not None and new['days_left'] < 14 and (old.get('days_left') or 99) >= 14:
            alerts.append(('high', f'Sertifikat TLS {target} kedaluwarsa dalam {new["days_left"]} hari', ''))
        if old.get('verified') and new.get('verified') is False:
            alerts.append(('high', f'Sertifikat TLS {target} tidak lagi valid', ''))
    elif check == 'subdomains':
        added, _ = _list_diff(old.get('names'), new.get('names'))
        if added:
            alerts.append(('medium', f'{len(added)} subdomain baru untuk {target}', ', '.join(added[:20])))
    elif check == 'intel':
        if old.get('verdict') != new.get('verdict') and new.get('verdict') in ('malicious', 'suspicious'):
            alerts.append(('high', f'{target} kini ditandai {new["verdict"]}', ', '.join(new.get('flagged_by', []))))
    elif check == 'typosquat':
        added, _ = _list_diff(old.get('registered'), new.get('registered'))
        if added:
            alerts.append(('high', f'{len(added)} domain tiruan baru terdaftar untuk {target}', ', '.join(added[:20])))
    elif check == 'ports':
        added, removed = _list_diff(old.get('ports'), new.get('ports'))
        if added:
            alerts.append(('high', f'Port baru terbuka di {target}', ', '.join(map(str, added))))
        if removed:
            alerts.append(('info', f'Port ditutup di {target}', ', '.join(map(str, removed))))
        vadded, _ = _list_diff(old.get('vulns'), new.get('vulns'))
        if vadded:
            alerts.append(('high', f'{len(vadded)} CVE baru terdeteksi di {target}', ', '.join(vadded[:20])))
    elif check == 'breaches':
        added, _ = _list_diff(old.get('breaches'), new.get('breaches'))
        if added:
            alerts.append(('high', f'{target} muncul di breach baru', ', '.join(added)))
    elif check == 'social':
        added, removed = _list_diff(old.get('profiles'), new.get('profiles'))
        if added or removed:
            alerts.append(('low', f'Profil sosial {target} berubah',
                           f'+ {", ".join(added) or "-"} / − {", ".join(removed) or "-"}'))
    return alerts


def run_watch(watch, progress=None):
    """Run all checks of one watch item, store snapshot, create & deliver alerts."""
    old_snapshot = watch.get('snapshot') or {}
    new_snapshot, errors, created = {}, {}, []
    for i, check in enumerate(watch['checks'], 1):
        if progress:
            progress(100 * (i - 1) / max(1, len(watch['checks'])), f'Cek {check}')
        try:
            new_snapshot[check] = CHECKS[check](watch['target'])
        except Exception as e:
            errors[check] = str(e)[:200]
            new_snapshot[check] = old_snapshot.get(check)  # keep last good value
            continue
        for severity, title, detail in diff(check, old_snapshot.get(check), new_snapshot[check], watch['target']):
            created.append({'severity': severity, 'title': title, 'detail': detail, 'check': check})

    first_run = not old_snapshot
    next_run = (datetime.now() + timedelta(minutes=watch['interval_min'])).strftime('%Y-%m-%d %H:%M:%S')
    status = 'error' if errors and len(errors) == len(watch['checks']) else \
        ('baseline' if first_run else f'{len(created)} perubahan')
    with db.connection() as conn:
        conn.execute('UPDATE watchlist SET snapshot_json = ?, last_run = ?, next_run = ?, last_status = ? WHERE id = ?',
                     (json.dumps(new_snapshot, default=str), casedb.now(), next_run, status, watch['id']))
        alert_ids = []
        for a in created:
            cur = conn.execute('INSERT INTO alerts (watch_id, case_id, ts, severity, title, detail, data_json)'
                               ' VALUES (?, ?, ?, ?, ?, ?, ?)',
                               (watch['id'], watch.get('case_id'), casedb.now(), a['severity'], a['title'],
                                a['detail'], json.dumps({'check': a['check']})))
            alert_ids.append(cur.lastrowid)
            if watch.get('case_id'):
                casedb.add_finding(conn, watch['case_id'], a['severity'], a['title'], a['detail'], 'watchlist')
                casedb._event(conn, watch['case_id'], 'alert', f'[{a["severity"]}] {a["title"]}')
    for alert_id, a in zip(alert_ids, created):
        delivery = deliver(watch, a)
        with db.connection() as conn:
            conn.execute('UPDATE alerts SET delivery_json = ? WHERE id = ?', (json.dumps(delivery), alert_id))
    return {'watch_id': watch['id'], 'target': watch['target'], 'status': status, 'alerts': created,
            'errors': errors, 'snapshot': new_snapshot}


# ── delivery ──
def _webhook_payload(url, watch, alert):
    text = f'[Motoku] [{alert["severity"].upper()}] {alert["title"]}\n{alert["detail"]}'
    if 'hooks.slack.com' in url:
        return {'text': text}
    if 'discord.com/api/webhooks' in url or 'discordapp.com/api/webhooks' in url:
        return {'content': text[:1900]}
    return {'source': 'motoku', 'watch': {'id': watch['id'], 'type': watch['type'], 'target': watch['target']},
            'case_id': watch.get('case_id'), 'alert': alert, 'ts': casedb.now()}


def deliver(watch, alert):
    notify = watch.get('notify') or {}
    webhooks = [u for u in [notify.get('webhook'), os.environ.get('MOTOKU_ALERT_WEBHOOK')] if u]
    emails = [e for e in [notify.get('email'), os.environ.get('MOTOKU_ALERT_EMAIL')] if e]
    min_sev = notify.get('min_severity') or os.environ.get('MOTOKU_ALERT_MIN_SEVERITY', 'low')
    order = ['info', 'low', 'medium', 'high', 'critical']
    result = {}
    if order.index(alert['severity']) < order.index(min_sev if min_sev in order else 'low'):
        return {'skipped': f'di bawah ambang {min_sev}'}
    for url in dict.fromkeys(webhooks):
        try:
            resp = requests.post(url, json=_webhook_payload(url, watch, alert), timeout=10,
                                 headers={'User-Agent': 'Motoku-OSINT/1.5'})
            result[f'webhook:{url[:40]}'] = resp.status_code
        except requests.RequestException as e:
            result[f'webhook:{url[:40]}'] = f'error {type(e).__name__}'
    for addr in dict.fromkeys(emails):
        try:
            send_email(addr, f'[Motoku] {alert["severity"].upper()}: {alert["title"]}',
                       f'{alert["title"]}\n\n{alert["detail"]}\n\nTarget: {watch["type"]} {watch["target"]}\n'
                       f'Case: {watch.get("case_id") or "-"}\nWaktu: {casedb.now()}')
            result[f'email:{addr}'] = 'sent'
        except Exception as e:
            result[f'email:{addr}'] = f'error {e}'[:120]
    return result


def send_email(to, subject, body):
    host = os.environ.get('MOTOKU_SMTP_HOST', '').strip()
    if not host:
        raise RuntimeError('MOTOKU_SMTP_HOST belum diatur')
    msg = EmailMessage()
    msg['From'] = os.environ.get('MOTOKU_SMTP_FROM', 'motoku@localhost')
    msg['To'] = to
    msg['Subject'] = subject
    msg.set_content(body)
    port = int(os.environ.get('MOTOKU_SMTP_PORT', '587'))
    with smtplib.SMTP(host, port, timeout=20) as smtp:
        if os.environ.get('MOTOKU_SMTP_STARTTLS', '1') == '1':
            smtp.starttls()
        user = os.environ.get('MOTOKU_SMTP_USER')
        if user:
            smtp.login(user, os.environ.get('MOTOKU_SMTP_PASSWORD', ''))
        smtp.send_message(msg)


# ── scheduler with a DB lease so only one process runs due checks ──
_owner = f'{socket.gethostname()}:{os.getpid()}'
_thread = None


def acquire_lease(name='watch-scheduler', ttl=120):
    now = time.time()
    with db.connection() as conn:
        conn.execute('INSERT INTO leases (name, owner, expires) VALUES (?, ?, ?)'
                     ' ON CONFLICT(name) DO UPDATE SET owner = excluded.owner, expires = excluded.expires'
                     ' WHERE leases.expires < ? OR leases.owner = excluded.owner',
                     (name, _owner, now + ttl, now))
        row = conn.execute('SELECT owner FROM leases WHERE name = ?', (name,)).fetchone()
    return row and row['owner'] == _owner


def run_due(enqueue=True):
    """Run (or enqueue as jobs) every due watch. Returns the processed watch ids."""
    from services import jobs
    processed = []
    for w in due():
        # Push next_run forward first so a slow check is not picked up twice.
        with db.connection() as conn:
            conn.execute('UPDATE watchlist SET next_run = ? WHERE id = ?',
                         ((datetime.now() + timedelta(minutes=w['interval_min'])).strftime('%Y-%m-%d %H:%M:%S'),
                          w['id']))
        if enqueue:
            jobs.enqueue('watch', f'{w["type"]}:{w["target"]}', {'watch_id': w['id']})
        else:
            run_watch(w)
        processed.append(w['id'])
    return processed


def start_scheduler(interval=60):
    global _thread
    if _thread and _thread.is_alive():
        return _thread

    def loop():
        while True:
            try:
                if acquire_lease(ttl=interval * 2):
                    run_due()
            except Exception:
                pass
            time.sleep(interval)

    _thread = threading.Thread(target=loop, name='motoku-watch-scheduler', daemon=True)
    _thread.start()
    return _thread
