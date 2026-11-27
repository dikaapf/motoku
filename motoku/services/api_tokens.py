"""API tokens for the REST API. Only a SHA-256 hash is stored; the plain
token is shown once at creation."""

import hashlib
import secrets

import db
from services.casedb import now

SCOPES = ('read', 'write', 'scan')


def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create(name, scopes=SCOPES):
    name = (name or '').strip()[:80]
    if not name:
        raise ValueError('Nama token wajib diisi')
    scopes = [s for s in scopes if s in SCOPES] or ['read']
    token = 'mtk_' + secrets.token_urlsafe(32)
    with db.connection() as conn:
        conn.execute('INSERT INTO api_tokens (name, prefix, token_hash, scopes, created_at) VALUES (?, ?, ?, ?, ?)',
                     (name, token[:10], _hash(token), ','.join(scopes), now()))
    return token


def verify(token):
    if not token or not token.startswith('mtk_'):
        return None
    with db.connection() as conn:
        row = conn.execute('SELECT * FROM api_tokens WHERE token_hash = ? AND revoked = 0', (_hash(token),)).fetchone()
        if not row:
            return None
        conn.execute('UPDATE api_tokens SET last_used = ? WHERE id = ?', (now(), row['id']))
    d = dict(row)
    d['scopes'] = d['scopes'].split(',')
    return d


def list_tokens():
    with db.connection() as conn:
        rows = conn.execute('SELECT id, name, prefix, scopes, created_at, last_used, revoked FROM api_tokens'
                            ' ORDER BY id DESC').fetchall()
    return [dict(r, scopes=r['scopes'].split(',')) for r in rows]


def revoke(token_id):
    with db.connection() as conn:
        conn.execute('UPDATE api_tokens SET revoked = 1 WHERE id = ?', (token_id,))
