"""Case report generation: Markdown, JSON, CSV (entities/findings/timeline),
standalone HTML and PDF (headless Chromium print of the HTML report)."""

import csv
import hashlib
import io
import json
import os
import subprocess
import tempfile
import zipfile
from datetime import datetime

from services import casedb

SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']


def build(case_id):
    case = casedb.get_case(case_id)
    if not case:
        raise ValueError('Case tidak ditemukan')
    entities = casedb.list_entities(case_id)
    findings = casedb.list_findings(case_id)
    by_type = {}
    for e in entities:
        by_type.setdefault(e['type'], []).append(e)
    open_f = [f for f in findings if f['status'] in ('open', 'confirmed')]
    sev = {s: sum(1 for f in open_f if f['severity'] == s) for s in SEV_ORDER}
    ids = {e['id']: e for e in entities}
    relations = [dict(r, src=ids.get(r['src_id'], {}).get('value'), src_type=ids.get(r['src_id'], {}).get('type'),
                      dst=ids.get(r['dst_id'], {}).get('value'), dst_type=ids.get(r['dst_id'], {}).get('type'))
                 for r in casedb.list_relations(case_id)]
    return {
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'case': case,
        'summary': {'entities': len(entities), 'relations': len(relations), 'findings_open': len(open_f),
                    'findings_total': len(findings), 'severity': sev,
                    'entity_types': {k: len(v) for k, v in sorted(by_type.items(), key=lambda kv: -len(kv[1]))}},
        'findings': findings,
        'entities': entities,
        'entities_by_type': by_type,
        'relations': relations,
        'notes': casedb.list_notes(case_id),
        'attachments': casedb.list_attachments(case_id),
        'timeline': casedb.list_events(case_id),
        'custody': casedb.verify_custody(case_id),
    }


def to_json(ctx):
    return json.dumps(ctx, indent=2, default=str, ensure_ascii=False)


def to_markdown(ctx):
    c = ctx['case']
    s = ctx['summary']
    out = [f'# Laporan Investigasi: {c["title"]}', '',
           f'- **Case ID:** `{c["id"]}`', f'- **Status:** {c["status"]}',
           f'- **Dibuat:** {c["created_at"]} · **Diperbarui:** {c["updated_at"]}',
           f'- **Laporan dibuat:** {ctx["generated_at"]}']
    if c.get('tags'):
        out.append(f'- **Tag:** {", ".join(c["tags"])}')
    out += ['', c.get('description') or '', '', '## Ringkasan', '',
            f'{s["entities"]} entity, {s["relations"]} relasi, {s["findings_open"]} temuan terbuka '
            f'(dari {s["findings_total"]}).', '',
            '| Severity | Jumlah |', '|---|---|']
    out += [f'| {k} | {v} |' for k, v in s['severity'].items()]
    out += ['', '## Temuan', '']
    if ctx['findings']:
        out += ['| # | Severity | Status | Temuan | Detail | Entity |', '|---|---|---|---|---|---|']
        for f in ctx['findings']:
            ent = f'{f["entity_type"]}: {f["entity_value"]}' if f.get('entity_value') else ''
            out.append(f'| {f["id"]} | {f["severity"]} | {f["status"]} | {_md(f["title"])} | {_md(f["detail"])} | {_md(ent)} |')
    else:
        out.append('_Tidak ada temuan._')
    out += ['', '## Entity', '']
    for etype, items in ctx['entities_by_type'].items():
        out += [f'### {etype} ({len(items)})', '']
        for e in items[:500]:
            label = f' — {e["label"]}' if e.get('label') else ''
            out.append(f'- `{e["value"]}`{_md(label)} _(sumber: {", ".join(e["sources"]) or "-"})_')
        out.append('')
    if ctx['relations']:
        out += ['## Relasi', '']
        out += [f'- `{r["src"]}` —{r["kind"]}→ `{r["dst"]}`' for r in ctx['relations'][:1000]]
        out.append('')
    if ctx['notes']:
        out += ['## Catatan', '']
        for n in ctx['notes']:
            out += [f'**{n["created_at"]}** ({n["author"] or "-"}):', '', n['body'], '']
    if ctx['attachments']:
        out += ['## Lampiran', '', '| File | SHA-256 | Ukuran | Ditambahkan |', '|---|---|---|---|']
        out += [f'| {_md(a["filename"])} | `{a["sha256"]}` | {a["size"]} | {a["created_at"]} |' for a in ctx['attachments']]
        out.append('')
    out += ['## Timeline', '']
    out += [f'- {e["ts"]} · **{e["kind"]}** · {_md(e["summary"])}' for e in reversed(ctx['timeline'])]
    cu = ctx['custody']
    out += ['', '## Chain of custody', '',
            f'{cu["count"]} catatan, integritas: **{"VALID" if cu["valid"] else "RUSAK pada #" + str(cu["broken_at"])}**'
            + (f', head `{cu.get("head")}`' if cu.get('head') else ''), '']
    return '\n'.join(out)


def _md(text):
    return (str(text or '')).replace('|', '\\|').replace('\n', ' ')


def _csv(rows, fields):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction='ignore')
    w.writeheader()
    for r in rows:
        w.writerow({k: (json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v) for k, v in r.items()})
    return '\ufeff' + buf.getvalue()


def to_csv_zip(ctx):
    """ZIP with entities.csv, findings.csv, relations.csv, timeline.csv."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('entities.csv', _csv(ctx['entities'], ['id', 'type', 'value', 'label', 'sources', 'tags',
                                                           'first_seen', 'last_seen', 'data']))
        z.writestr('findings.csv', _csv(ctx['findings'], ['id', 'severity', 'status', 'title', 'detail', 'source',
                                                           'entity_type', 'entity_value', 'created_at']))
        z.writestr('relations.csv', _csv(ctx['relations'], ['src_type', 'src', 'kind', 'dst_type', 'dst', 'source',
                                                             'created_at']))
        z.writestr('timeline.csv', _csv(ctx['timeline'], ['ts', 'kind', 'summary']))
        z.writestr('custody.csv', _csv(casedb.custody_log(ctx['case']['id']),
                                       ['id', 'ts', 'actor', 'action', 'object_type', 'object_id', 'digest',
                                        'prev_hash', 'hash']))
    return buf.getvalue()


def chromium_available():
    from tools.http_probe import _chromium_binary
    return _chromium_binary() is not None


def html_to_pdf(html):
    from tools.http_probe import _chromium_binary
    binary = _chromium_binary()
    if not binary:
        raise RuntimeError('Chromium tidak ditemukan — gunakan ekspor HTML lalu cetak ke PDF dari browser')
    with tempfile.TemporaryDirectory(prefix='motoku-report-') as tmp:
        src = os.path.join(tmp, 'report.html')
        out = os.path.join(tmp, 'report.pdf')
        with open(src, 'w', encoding='utf-8') as fh:
            fh.write(html)
        cmd = [binary, '--headless=new', '--no-sandbox', '--disable-gpu', f'--user-data-dir={tmp}/profile',
               '--no-pdf-header-footer', f'--print-to-pdf={out}', f'file://{src}']
        try:
            subprocess.run(cmd, capture_output=True, timeout=90, check=False)
        except (subprocess.TimeoutExpired, OSError) as e:
            raise RuntimeError(f'Gagal membuat PDF: {type(e).__name__}')
        if not os.path.exists(out) or os.path.getsize(out) == 0:
            raise RuntimeError('Chromium tidak menghasilkan PDF')
        with open(out, 'rb') as fh:
            return fh.read()


def digest(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()
