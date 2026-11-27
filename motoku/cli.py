#!/usr/bin/env python3
"""Motoku command-line client (talks to the REST API).

    export MOTOKU_URL=http://127.0.0.1:5000
    export MOTOKU_TOKEN=mtk_...

    python cli.py detect example.com
    python cli.py tool dns-security example.com
    python cli.py recon example.com --case <case_id> --wait
    python cli.py job status <job_id>
    python cli.py case list | case create "Judul" | case show <id> | case report <id> --format md
    python cli.py case add-entity <id> domain example.com
    python cli.py watch add domain example.com --case <id>
    python cli.py alerts --unacked

``python cli.py watch-run`` runs due watchlist checks locally (no API; for cron).
"""

import argparse
import json
import os
import sys
import time

import requests


class Client:
    def __init__(self, url, token, timeout=120):
        self.url = url.rstrip('/') + '/api/v1'
        self.session = requests.Session()
        self.session.headers.update({'Authorization': f'Bearer {token}', 'User-Agent': 'motoku-cli/1.0'})
        self.timeout = timeout

    def _do(self, method, path, **kw):
        resp = self.session.request(method, self.url + path, timeout=self.timeout, **kw)
        ctype = resp.headers.get('Content-Type', '')
        body = resp.json() if 'json' in ctype else resp.text
        if resp.status_code >= 400:
            msg = body.get('error') if isinstance(body, dict) else body
            raise SystemExit(f'Error {resp.status_code}: {msg}')
        return body

    def get(self, path, **params):
        return self._do('GET', path, params={k: v for k, v in params.items() if v is not None})

    def post(self, path, payload):
        return self._do('POST', path, json=payload)


def out(data, as_json):
    if isinstance(data, str):
        print(data)
    elif as_json:
        print(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    else:
        print(json.dumps(data, indent=2, ensure_ascii=False, default=str)[:20000])


def wait_job(client, job_id, quiet=False):
    last = None
    while True:
        job = client.get(f'/jobs/{job_id}', result='0')
        line = f'[{job["status"]:>8}] {job["progress"]:>3}% {job.get("message") or ""}'
        if line != last and not quiet:
            print(line, file=sys.stderr)
            last = line
        if job['status'] in ('finished', 'failed'):
            return client.get(f'/jobs/{job_id}')
        time.sleep(2)


def main(argv=None):
    p = argparse.ArgumentParser(prog='motoku', description='Motoku OSINT CLI')
    p.add_argument('--url', default=os.environ.get('MOTOKU_URL', 'http://127.0.0.1:5000'))
    p.add_argument('--token', default=os.environ.get('MOTOKU_TOKEN'))
    p.add_argument('--json', action='store_true', help='output JSON lengkap')
    sub = p.add_subparsers(dest='cmd', required=True)

    s = sub.add_parser('detect', help='deteksi tipe input')
    s.add_argument('query')

    sub.add_parser('tools', help='daftar tool sinkron')
    s = sub.add_parser('tool', help='jalankan tool sinkron')
    s.add_argument('name')
    s.add_argument('value')
    s.add_argument('--case')

    s = sub.add_parser('recon', help='recon domain lengkap (job)')
    s.add_argument('domain')
    s.add_argument('--case')
    s.add_argument('--no-ports', action='store_true')
    s.add_argument('--wait', action='store_true')

    s = sub.add_parser('job', help='job background')
    jsub = s.add_subparsers(dest='job_cmd', required=True)
    j = jsub.add_parser('start')
    j.add_argument('kind')
    j.add_argument('params', help='JSON params, mis. \'{"domain": "example.com"}\'')
    j.add_argument('--wait', action='store_true')
    j = jsub.add_parser('status')
    j.add_argument('job_id')
    j.add_argument('--wait', action='store_true')

    s = sub.add_parser('case', help='kelola case')
    csub = s.add_subparsers(dest='case_cmd', required=True)
    c = csub.add_parser('list')
    c.add_argument('--status')
    c = csub.add_parser('create')
    c.add_argument('title')
    c.add_argument('--description', default='')
    c.add_argument('--tags', default='')
    c = csub.add_parser('show')
    c.add_argument('case_id')
    c = csub.add_parser('report')
    c.add_argument('case_id')
    c.add_argument('--format', choices=['json', 'md'], default='md')
    c = csub.add_parser('add-entity')
    c.add_argument('case_id')
    c.add_argument('type')
    c.add_argument('value')
    c.add_argument('--label')
    c = csub.add_parser('note')
    c.add_argument('case_id')
    c.add_argument('body')
    c = csub.add_parser('import-job')
    c.add_argument('case_id')
    c.add_argument('job_id')

    s = sub.add_parser('watch', help='watchlist')
    wsub = s.add_subparsers(dest='watch_cmd', required=True)
    wsub.add_parser('list')
    w = wsub.add_parser('add')
    w.add_argument('type', choices=['domain', 'ip', 'email', 'username'])
    w.add_argument('target')
    w.add_argument('--case')
    w.add_argument('--interval', type=int, default=1440)
    w.add_argument('--webhook')

    s = sub.add_parser('alerts', help='daftar alert')
    s.add_argument('--case')
    s.add_argument('--unacked', action='store_true')

    sub.add_parser('watch-run', help='jalankan watchlist yang jatuh tempo secara lokal (untuk cron)')

    a = p.parse_args(argv)

    if a.cmd == 'watch-run':
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import db
        from services import (
            job_handlers,  # noqa: F401
            watch,
        )
        db.configure()
        processed = watch.run_due(enqueue=False)
        print(f'{len(processed)} watch dijalankan: {processed}')
        return 0

    if not a.token:
        raise SystemExit('Set MOTOKU_TOKEN atau --token (buat di /settings/tokens)')
    cl = Client(a.url, a.token)

    if a.cmd == 'detect':
        r = cl.get('/detect', q=a.query)
        if a.json:
            out(r, True)
        else:
            print(f'{r["value"]} → {r["type_label"]}')
            for t in r['tools']:
                print(f'  - {t["label"]}  ({t["endpoint"]}: {t["value"]})')
    elif a.cmd == 'tools':
        for name, desc in cl.get('/tools').items():
            print(f'{name:14} {desc}')
    elif a.cmd == 'tool':
        r = cl.post(f'/tools/{a.name}', {'value': a.value, 'case_id': a.case})
        out(r if a.json else r['result'], a.json)
        if r.get('case_import'):
            print(f'→ diimpor ke case: {r["case_import"]}', file=sys.stderr)
    elif a.cmd == 'recon':
        r = cl.post('/jobs', {'kind': 'recon', 'case_id': a.case,
                              'params': {'domain': a.domain, 'options': {'ports': not a.no_ports}}})
        print(f'job {r["job_id"]}', file=sys.stderr)
        if a.wait:
            job = wait_job(cl, r['job_id'])
            result = job.get('result') or {}
            if a.json:
                out(job, True)
            else:
                for f in (result.get('summary') or {}).get('findings', []):
                    print(f'[{f["severity"]:>8}] {f["title"]} — {f["detail"][:100]}')
                if job.get('error'):
                    print('error:', job['error'])
    elif a.cmd == 'job':
        if a.job_cmd == 'start':
            r = cl.post('/jobs', {'kind': a.kind, 'params': json.loads(a.params)})
            print(r['job_id'])
            if a.wait:
                out(wait_job(cl, r['job_id']), a.json)
        else:
            out(wait_job(cl, a.job_id) if a.wait else cl.get(f'/jobs/{a.job_id}'), a.json)
    elif a.cmd == 'case':
        if a.case_cmd == 'list':
            for c in ([] if a.json else cl.get('/cases', status=a.status)):
                print(f'{c["id"]}  [{c["status"]:>6}]  {c["entity_count"]:>4} entity  {c["open_findings"]:>3} temuan  {c["title"]}')
            if a.json:
                out(cl.get('/cases', status=a.status), True)
        elif a.case_cmd == 'create':
            r = cl.post('/cases', {'title': a.title, 'description': a.description, 'tags': a.tags})
            print(r['id'])
        elif a.case_cmd == 'show':
            out(cl.get(f'/cases/{a.case_id}'), True)
        elif a.case_cmd == 'report':
            out(cl.get(f'/cases/{a.case_id}/report', format=a.format), a.format == 'json')
        elif a.case_cmd == 'add-entity':
            out(cl.post(f'/cases/{a.case_id}/entities', {'type': a.type, 'value': a.value, 'label': a.label}), True)
        elif a.case_cmd == 'note':
            out(cl.post(f'/cases/{a.case_id}/notes', {'body': a.body}), True)
        elif a.case_cmd == 'import-job':
            out(cl.post(f'/cases/{a.case_id}/import', {'job_id': a.job_id}), True)
    elif a.cmd == 'watch':
        if a.watch_cmd == 'list':
            items = cl.get('/watchlist')
            if a.json:
                out(items, True)
            for w in [] if a.json else items:
                print(f'#{w["id"]:<4} {w["type"]:8} {w["target"]:40} {w["last_status"] or "-"}')
        else:
            out(cl.post('/watchlist', {'type': a.type, 'target': a.target, 'case_id': a.case,
                                       'interval_min': a.interval, 'notify': {'webhook': a.webhook}}), True)
    elif a.cmd == 'alerts':
        items = cl.get('/alerts', case_id=a.case, unacked='1' if a.unacked else None)
        if a.json:
            out(items, True)
        for al in [] if a.json else items:
            print(f'{al["ts"]} [{al["severity"]:>8}] {al["title"]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
