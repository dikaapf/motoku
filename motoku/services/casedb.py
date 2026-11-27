"""Case/workspace data access: cases → entities (+relations) → findings,
notes, attachments, timeline events and a tamper-evident chain of custody.

Chain of custody: every state change appends a record whose ``hash`` is
SHA-256 over the previous record's hash and the canonical JSON of this record.
Editing or deleting any past record breaks :func:`verify_custody`.
"""

import hashlib
import json
import os
import re
import secrets
from datetime import datetime

import db

ATTACHMENT_DIR = os.environ.get('MOTOKU_ATTACHMENT_DIR',
                                os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'attachments'))
SEVERITIES = ('critical', 'high', 'medium', 'low', 'info')
FINDING_STATUSES = ('open', 'confirmed', 'false_positive', 'resolved')
CASE_STATUSES = ('open', 'closed', 'archived')
ENTITY_TYPES = {
    'domain': ('bi-globe', '#00ff88'), 'subdomain': ('bi-diagram-3', '#00ccff'),
    'ip': ('bi-hdd-network', '#ff8800'), 'service': ('bi-plug', '#ff6666'),
    'url': ('bi-link-45deg', '#88ddff'), 'email': ('bi-envelope', '#ff66cc'),
    'phone': ('bi-telephone', '#66ff66'), 'username': ('bi-at', '#ffcc00'),
    'account': ('bi-person-badge', '#ffaa44'), 'person': ('bi-person', '#ffffff'),
    'organization': ('bi-building', '#aa88ff'), 'location': ('bi-geo-alt', '#ff4444'),
    'cve': ('bi-bug', '#ff3333'), 'hash': ('bi-hash', '#cccccc'), 'file': ('bi-file-earmark', '#cccccc'),
    'certificate': ('bi-lock', '#66ccff'), 'bucket': ('bi-bucket', '#33ccff'),
    'asn': ('bi-diagram-2', '#ffbb66'), 'other': ('bi-question-circle', '#999999'),
}


def now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _dump(value):
    return json.dumps(value, default=str, sort_keys=True, ensure_ascii=False) if value is not None else None


def _load(raw, default=None):
    return json.loads(raw) if raw else default


# ── custody & events ──
def _custody(conn, case_id, actor, action, object_type=None, object_id=None, digest=None):
    prev = conn.execute('SELECT hash FROM custody WHERE case_id = ? ORDER BY id DESC LIMIT 1', (case_id,)).fetchone()
    prev_hash = prev['hash'] if prev else '0' * 64
    record = {'case_id': case_id, 'ts': now(), 'actor': actor or 'system', 'action': action,
              'object_type': object_type, 'object_id': str(object_id) if object_id is not None else None,
              'digest': digest}
    h = hashlib.sha256((prev_hash + _dump(record)).encode()).hexdigest()
    conn.execute('INSERT INTO custody (case_id, ts, actor, action, object_type, object_id, digest, prev_hash, hash)'
                 ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                 (case_id, record['ts'], record['actor'], action, object_type, record['object_id'], digest,
                  prev_hash, h))


def _event(conn, case_id, kind, summary, data=None):
    conn.execute('INSERT INTO events (case_id, ts, kind, summary, data_json) VALUES (?, ?, ?, ?, ?)',
                 (case_id, now(), kind, summary[:500], _dump(data)))
    conn.execute('UPDATE cases SET updated_at = ? WHERE id = ?', (now(), case_id))


def custody_log(case_id):
    with db.connection() as conn:
        return [dict(r) for r in conn.execute('SELECT * FROM custody WHERE case_id = ? ORDER BY id', (case_id,))]


def verify_custody(case_id):
    """Recompute the hash chain; returns ``{'valid': bool, 'count': n, 'broken_at': id|None}``."""
    prev_hash = '0' * 64
    rows = custody_log(case_id)
    for r in rows:
        record = {'case_id': r['case_id'], 'ts': r['ts'], 'actor': r['actor'], 'action': r['action'],
                  'object_type': r['object_type'], 'object_id': r['object_id'], 'digest': r['digest']}
        expected = hashlib.sha256((prev_hash + _dump(record)).encode()).hexdigest()
        if r['prev_hash'] != prev_hash or r['hash'] != expected:
            return {'valid': False, 'count': len(rows), 'broken_at': r['id']}
        prev_hash = r['hash']
    return {'valid': True, 'count': len(rows), 'broken_at': None, 'head': prev_hash}


# ── cases ──
def create_case(title, description='', tags=None, actor=None):
    title = (title or '').strip()
    if not title:
        raise ValueError('Judul case wajib diisi')
    case_id = datetime.now().strftime('%Y%m%d') + '-' + secrets.token_hex(3)
    with db.connection() as conn:
        conn.execute('INSERT INTO cases (id, title, description, status, tags_json, created_at, updated_at)'
                     " VALUES (?, ?, ?, 'open', ?, ?, ?)",
                     (case_id, title[:200], description or '', _dump(_clean_tags(tags)), now(), now()))
        _event(conn, case_id, 'case', f'Case dibuat: {title}')
        _custody(conn, case_id, actor, 'case.create', 'case', case_id,
                 hashlib.sha256(_dump({'title': title, 'description': description}).encode()).hexdigest())
    return case_id


def _clean_tags(tags):
    if isinstance(tags, str):
        tags = tags.split(',')
    return sorted({t.strip().lower() for t in (tags or []) if t and t.strip()})[:30]


def _case_row(r):
    if r is None:
        return None
    d = dict(r)
    d['tags'] = _load(d.pop('tags_json'), [])
    return d


def get_case(case_id):
    with db.connection() as conn:
        return _case_row(conn.execute('SELECT * FROM cases WHERE id = ?', (case_id,)).fetchone())


def list_cases(status=None, limit=100):
    sql = ('SELECT c.*, (SELECT COUNT(*) FROM entities e WHERE e.case_id = c.id) AS entity_count,'
           " (SELECT COUNT(*) FROM findings f WHERE f.case_id = c.id AND f.status IN ('open', 'confirmed')) AS open_findings"
           ' FROM cases c')
    args = []
    if status:
        sql += ' WHERE c.status = ?'
        args.append(status)
    sql += ' ORDER BY c.updated_at DESC LIMIT ?'
    args.append(limit)
    with db.connection() as conn:
        return [_case_row(r) for r in conn.execute(sql, args)]


def update_case(case_id, actor=None, **fields):
    allowed = {}
    if 'title' in fields and fields['title']:
        allowed['title'] = fields['title'].strip()[:200]
    if 'description' in fields and fields['description'] is not None:
        allowed['description'] = fields['description']
    if 'status' in fields and fields['status'] in CASE_STATUSES:
        allowed['status'] = fields['status']
    if 'tags' in fields and fields['tags'] is not None:
        allowed['tags_json'] = _dump(_clean_tags(fields['tags']))
    if not allowed:
        return
    with db.connection() as conn:
        sets = ', '.join(f'{k} = ?' for k in allowed)
        conn.execute(f'UPDATE cases SET {sets}, updated_at = ? WHERE id = ?', [*allowed.values(), now(), case_id])
        _event(conn, case_id, 'case', 'Case diperbarui: ' + ', '.join(k.replace('_json', '') for k in allowed))
        _custody(conn, case_id, actor, 'case.update', 'case', case_id,
                 hashlib.sha256(_dump(allowed).encode()).hexdigest())


def delete_case(case_id):
    with db.connection() as conn:
        conn.execute('DELETE FROM cases WHERE id = ?', (case_id,))
        conn.execute('DELETE FROM custody WHERE case_id = ?', (case_id,))
    folder = os.path.join(ATTACHMENT_DIR, _safe_id(case_id))
    if os.path.isdir(folder):
        for name in os.listdir(folder):
            os.remove(os.path.join(folder, name))
        os.rmdir(folder)


def _safe_id(case_id):
    if not re.match(r'^[A-Za-z0-9\-]+$', case_id or ''):
        raise ValueError('ID case tidak valid')
    return case_id


# ── entities & relations ──
def normalise_value(etype, value):
    value = str(value).strip()
    if etype in ('domain', 'subdomain', 'email', 'username', 'hash'):
        value = value.lower().rstrip('.')
    if etype == 'cve':
        value = value.upper()
    return value[:500]


def upsert_entity(conn, case_id, etype, value, label=None, data=None, source=None, tags=None):
    etype = etype if etype in ENTITY_TYPES else 'other'
    value = normalise_value(etype, value)
    if not value:
        return None, False
    row = conn.execute('SELECT * FROM entities WHERE case_id = ? AND type = ? AND value = ?',
                       (case_id, etype, value)).fetchone()
    ts = now()
    if row:
        merged = {**(_load(row['data_json'], {}) or {}), **(data or {})}
        sources = sorted(set(_load(row['sources_json'], []) + ([source] if source else [])))
        all_tags = sorted(set(_load(row['tags_json'], []) + _clean_tags(tags)))
        conn.execute('UPDATE entities SET label = COALESCE(?, label), data_json = ?, sources_json = ?,'
                     ' tags_json = ?, last_seen = ? WHERE id = ?',
                     (label, _dump(merged), _dump(sources), _dump(all_tags), ts, row['id']))
        return row['id'], False
    cur = conn.execute('INSERT INTO entities (case_id, type, value, label, data_json, sources_json, tags_json,'
                       ' first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                       (case_id, etype, value, label, _dump(data or {}), _dump([source] if source else []),
                        _dump(_clean_tags(tags)), ts, ts))
    return cur.lastrowid, True


def add_relation(conn, case_id, src_id, dst_id, kind, source=None):
    if not src_id or not dst_id or src_id == dst_id:
        return False
    cur = conn.execute('INSERT OR IGNORE INTO relations (case_id, src_id, dst_id, kind, source, created_at)'
                       ' VALUES (?, ?, ?, ?, ?, ?)', (case_id, src_id, dst_id, kind, source, now()))
    return cur.rowcount > 0


def add_entity(case_id, etype, value, label=None, data=None, source='manual', actor=None, tags=None):
    with db.connection() as conn:
        eid, created = upsert_entity(conn, case_id, etype, value, label, data, source, tags)
        if eid is None:
            raise ValueError('Nilai entity kosong')
        if created:
            _event(conn, case_id, 'entity', f'Entity ditambahkan: {etype} {value}')
            _custody(conn, case_id, actor, 'entity.add', 'entity', eid,
                     hashlib.sha256(f'{etype}:{normalise_value(etype, value)}'.encode()).hexdigest())
    return eid


def delete_entity(case_id, entity_id, actor=None):
    with db.connection() as conn:
        row = conn.execute('SELECT type, value FROM entities WHERE id = ? AND case_id = ?', (entity_id, case_id)).fetchone()
        if not row:
            return False
        conn.execute('DELETE FROM entities WHERE id = ?', (entity_id,))
        _event(conn, case_id, 'entity', f'Entity dihapus: {row["type"]} {row["value"]}')
        _custody(conn, case_id, actor, 'entity.delete', 'entity', entity_id)
    return True


def _entity_row(r):
    d = dict(r)
    d['data'] = _load(d.pop('data_json'), {})
    d['sources'] = _load(d.pop('sources_json'), [])
    d['tags'] = _load(d.pop('tags_json'), [])
    return d


def list_entities(case_id, etype=None):
    sql, args = 'SELECT * FROM entities WHERE case_id = ?', [case_id]
    if etype:
        sql += ' AND type = ?'
        args.append(etype)
    sql += ' ORDER BY type, value'
    with db.connection() as conn:
        return [_entity_row(r) for r in conn.execute(sql, args)]


def list_relations(case_id):
    with db.connection() as conn:
        return [dict(r) for r in conn.execute('SELECT * FROM relations WHERE case_id = ?', (case_id,))]


def entity_counts(case_id):
    with db.connection() as conn:
        return {r['type']: r['n'] for r in conn.execute(
            'SELECT type, COUNT(*) AS n FROM entities WHERE case_id = ? GROUP BY type ORDER BY n DESC', (case_id,))}


# ── findings ──
def add_finding(conn, case_id, severity, title, detail='', source=None, entity_id=None):
    severity = severity if severity in SEVERITIES else 'info'
    fingerprint = hashlib.sha1(f'{title}|{detail}'.encode()).hexdigest()
    cur = conn.execute('INSERT OR IGNORE INTO findings (case_id, entity_id, severity, title, detail, source,'
                       " status, fingerprint, created_at) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)",
                       (case_id, entity_id, severity, title[:300], (detail or '')[:2000], source, fingerprint, now()))
    return cur.rowcount > 0


def create_finding(case_id, severity, title, detail='', actor=None, entity_id=None):
    with db.connection() as conn:
        created = add_finding(conn, case_id, severity, title, detail, 'manual', entity_id)
        if created:
            _event(conn, case_id, 'finding', f'[{severity}] {title}')
            _custody(conn, case_id, actor, 'finding.add', 'finding', title[:60])
    return created


def set_finding_status(case_id, finding_id, status, actor=None):
    if status not in FINDING_STATUSES:
        raise ValueError('Status tidak valid')
    with db.connection() as conn:
        cur = conn.execute('UPDATE findings SET status = ? WHERE id = ? AND case_id = ?', (status, finding_id, case_id))
        if cur.rowcount:
            _event(conn, case_id, 'finding', f'Temuan #{finding_id} → {status}')
            _custody(conn, case_id, actor, 'finding.status', 'finding', finding_id, status)


def list_findings(case_id, include_closed=True):
    order = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
    sql = 'SELECT f.*, e.type AS entity_type, e.value AS entity_value FROM findings f' \
          ' LEFT JOIN entities e ON e.id = f.entity_id WHERE f.case_id = ?'
    if not include_closed:
        sql += " AND f.status IN ('open', 'confirmed')"
    sql += f' ORDER BY {order}, f.id'
    with db.connection() as conn:
        return [dict(r) for r in conn.execute(sql, (case_id,))]


# ── notes ──
def add_note(case_id, body, actor=None, entity_id=None):
    body = (body or '').strip()
    if not body:
        raise ValueError('Catatan kosong')
    with db.connection() as conn:
        cur = conn.execute('INSERT INTO notes (case_id, entity_id, body, author, created_at) VALUES (?, ?, ?, ?, ?)',
                           (case_id, entity_id, body[:20000], actor, now()))
        _event(conn, case_id, 'note', f'Catatan: {body[:120]}')
        _custody(conn, case_id, actor, 'note.add', 'note', cur.lastrowid, hashlib.sha256(body.encode()).hexdigest())
    return cur.lastrowid


def list_notes(case_id):
    with db.connection() as conn:
        return [dict(r) for r in conn.execute(
            'SELECT n.*, e.type AS entity_type, e.value AS entity_value FROM notes n'
            ' LEFT JOIN entities e ON e.id = n.entity_id WHERE n.case_id = ? ORDER BY n.id DESC', (case_id,))]


# ── attachments ──
def add_attachment(case_id, filename, data, mime=None, note=None, actor=None):
    if not data:
        raise ValueError('File kosong')
    digest = hashlib.sha256(data).hexdigest()
    folder = os.path.join(ATTACHMENT_DIR, _safe_id(case_id))
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, digest)
    if not os.path.exists(path):
        with open(path, 'wb') as fh:
            fh.write(data)
    safe_name = re.sub(r'[^\w.\- ]', '_', os.path.basename(filename or 'file'))[:150] or 'file'
    with db.connection() as conn:
        cur = conn.execute('INSERT INTO attachments (case_id, filename, sha256, size, mime, note, author, created_at)'
                           ' VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                           (case_id, safe_name, digest, len(data), mime, note, actor, now()))
        upsert_entity(conn, case_id, 'hash', digest, label=safe_name, data={'algo': 'sha256', 'size': len(data)},
                      source='attachment')
        _event(conn, case_id, 'attachment', f'Lampiran: {safe_name} ({len(data)} B)')
        _custody(conn, case_id, actor, 'attachment.add', 'attachment', cur.lastrowid, digest)
    return cur.lastrowid


def list_attachments(case_id):
    with db.connection() as conn:
        return [dict(r) for r in conn.execute('SELECT * FROM attachments WHERE case_id = ? ORDER BY id DESC', (case_id,))]


def get_attachment(case_id, attachment_id, actor=None):
    with db.connection() as conn:
        row = conn.execute('SELECT * FROM attachments WHERE id = ? AND case_id = ?', (attachment_id, case_id)).fetchone()
        if not row:
            return None, None
        path = os.path.join(ATTACHMENT_DIR, _safe_id(case_id), row['sha256'])
        with open(path, 'rb') as fh:
            data = fh.read()
        intact = hashlib.sha256(data).hexdigest() == row['sha256']
        _custody(conn, case_id, actor, 'attachment.access', 'attachment', attachment_id,
                 row['sha256'] if intact else 'MISMATCH')
    return dict(row, intact=intact), data


# ── timeline ──
def list_events(case_id, limit=500):
    with db.connection() as conn:
        rows = conn.execute('SELECT * FROM events WHERE case_id = ? ORDER BY ts DESC, id DESC LIMIT ?',
                            (case_id, limit)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d['data'] = _load(d.pop('data_json'), None)
        out.append(d)
    return out


def log_export(case_id, fmt, digest, actor=None):
    with db.connection() as conn:
        _event(conn, case_id, 'report', f'Laporan diekspor ({fmt})')
        _custody(conn, case_id, actor, 'report.export', 'report', fmt, digest)


# ── bulk import (used by services.importer) ──
def import_bundle(case_id, bundle, source, actor=None, summary=None):
    """Persist ``bundle`` = {'entities': [...], 'relations': [...], 'findings': [...]}.

    Entities are dicts with ``key`` (local id), ``type``, ``value`` and optional
    ``label``/``data``/``tags``; relations reference those keys.
    """
    stats = {'entities_new': 0, 'entities_updated': 0, 'relations': 0, 'findings': 0}
    ids = {}
    with db.connection() as conn:
        if not conn.execute('SELECT 1 FROM cases WHERE id = ?', (case_id,)).fetchone():
            raise ValueError('Case tidak ditemukan')
        for ent in bundle.get('entities', []):
            eid, created = upsert_entity(conn, case_id, ent['type'], ent['value'], ent.get('label'),
                                         ent.get('data'), source, ent.get('tags'))
            if eid:
                ids[ent.get('key') or (ent['type'], ent['value'])] = eid
                stats['entities_new' if created else 'entities_updated'] += 1
        for rel in bundle.get('relations', []):
            if add_relation(conn, case_id, ids.get(rel['src']), ids.get(rel['dst']), rel['kind'], source):
                stats['relations'] += 1
        for f in bundle.get('findings', []):
            if add_finding(conn, case_id, f.get('severity', 'info'), f['title'], f.get('detail', ''), source,
                           ids.get(f.get('entity'))):
                stats['findings'] += 1
        digest = hashlib.sha256(_dump(bundle).encode()).hexdigest()
        _event(conn, case_id, 'import',
               summary or f'Import dari {source}: {stats["entities_new"]} entity baru, {stats["findings"]} temuan',
               {'source': source, **stats})
        _custody(conn, case_id, actor, 'import', 'source', source, digest)
    stats['digest'] = digest
    return stats
