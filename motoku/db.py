"""SQLite persistence layer.

Replaces the previous JSON-file storage for tracking records and CCTV cameras.
The module uses the standard-library ``sqlite3`` driver, which keeps the
deployment dependency-free while still providing transactions, WAL concurrency,
and a simple migration path from the legacy JSON files.
"""

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
DEFAULT_DB_PATH = os.path.join(DATA_DIR, 'motoku.db')
LEGACY_TRACKING_FILE = os.path.join(DATA_DIR, 'tracking.json')
LEGACY_CAMERAS_FILE = os.path.join(DATA_DIR, 'cctv_indonesia.json')

SCHEMA = """
CREATE TABLE IF NOT EXISTS tracking (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    location_json TEXT,
    device_info_json TEXT
);

CREATE TABLE IF NOT EXISTS cameras (
    id TEXT PRIMARY KEY,
    name TEXT,
    city TEXT,
    district TEXT,
    province TEXT,
    lat REAL,
    lng REAL,
    source TEXT,
    source_url TEXT,
    type TEXT,
    url TEXT,
    status TEXT,
    kode_kabupaten TEXT
);
CREATE INDEX IF NOT EXISTS idx_cameras_city ON cameras(city);
CREATE INDEX IF NOT EXISTS idx_cameras_province ON cameras(province);

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    target TEXT,
    params_json TEXT,
    status TEXT NOT NULL DEFAULT 'queued',
    progress INTEGER NOT NULL DEFAULT 0,
    message TEXT,
    log_json TEXT,
    partial_json TEXT,
    result_json TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_kind_created ON jobs(kind, created_at);

CREATE TABLE IF NOT EXISTS provider_usage (
    provider TEXT PRIMARY KEY,
    calls INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    cache_hits INTEGER NOT NULL DEFAULT 0,
    last_called_at TEXT
);
"""

CAMERA_FIELDS = [
    'id', 'name', 'city', 'district', 'province', 'lat', 'lng',
    'source', 'source_url', 'type', 'url', 'status', 'kode_kabupaten',
]

_db_path = None
_init_lock = threading.Lock()


def configure(path=None, migrate=True):
    """Point the module at a database file and initialise the schema."""
    global _db_path
    _db_path = path or os.environ.get('MOTOKU_DB_PATH') or DEFAULT_DB_PATH
    parent = os.path.dirname(os.path.abspath(_db_path))
    os.makedirs(parent, exist_ok=True)

    with _init_lock:
        _init_schema()
        if migrate:
            _migrate_legacy_files()


def get_db_path():
    return _db_path or os.environ.get('MOTOKU_DB_PATH') or DEFAULT_DB_PATH


def get_connection():
    conn = sqlite3.connect(get_db_path(), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


@contextmanager
def connection():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _init_schema():
    with connection() as conn:
        conn.executescript(SCHEMA)
        _add_missing_columns(conn)


# Columns added after the first release; applied idempotently on start-up.
_COLUMN_MIGRATIONS = [
    ('provider_usage', 'cache_hits', 'INTEGER NOT NULL DEFAULT 0'),
]


def _add_missing_columns(conn):
    for table, column, ddl in _COLUMN_MIGRATIONS:
        existing = {row[1] for row in conn.execute(f'PRAGMA table_info({table})')}
        if column not in existing:
            conn.execute(f'ALTER TABLE {table} ADD COLUMN {column} {ddl}')


def _now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _migrate_legacy_files():
    """Import legacy JSON data once, when the target tables are empty."""
    with connection() as conn:
        tracking_count = conn.execute('SELECT COUNT(*) FROM tracking').fetchone()[0]
        if tracking_count == 0 and os.path.exists(LEGACY_TRACKING_FILE):
            try:
                with open(LEGACY_TRACKING_FILE, encoding='utf-8') as handle:
                    legacy = json.load(handle)
            except (OSError, ValueError):
                legacy = {}
            for tracking_id, item in legacy.items():
                conn.execute(
                    'INSERT OR IGNORE INTO tracking'
                    ' (id, label, created_at, status, location_json, device_info_json)'
                    ' VALUES (?, ?, ?, ?, ?, ?)',
                    (
                        tracking_id,
                        item.get('label') or 'Tanpa Label',
                        item.get('created_at') or _now(),
                        item.get('status') or 'pending',
                        json.dumps(item['location']) if item.get('location') else None,
                        json.dumps(item['device_info']) if item.get('device_info') else None,
                    ),
                )

        camera_count = conn.execute('SELECT COUNT(*) FROM cameras').fetchone()[0]
        if camera_count == 0 and os.path.exists(LEGACY_CAMERAS_FILE):
            try:
                with open(LEGACY_CAMERAS_FILE, encoding='utf-8') as handle:
                    legacy = json.load(handle)
            except (OSError, ValueError):
                legacy = {}
            rows = [
                tuple(cam.get(field) for field in CAMERA_FIELDS)
                for cam in legacy.get('cameras', [])
                if cam.get('id')
            ]
            if rows:
                placeholders = ', '.join('?' for _ in CAMERA_FIELDS)
                conn.executemany(
                    f'INSERT OR IGNORE INTO cameras ({", ".join(CAMERA_FIELDS)})'
                    f' VALUES ({placeholders})',
                    rows,
                )


# ── Tracking ──

def _track_from_row(row):
    if row is None:
        return None
    return {
        'label': row['label'],
        'created_at': row['created_at'],
        'status': row['status'],
        'location': json.loads(row['location_json']) if row['location_json'] else None,
        'device_info': json.loads(row['device_info_json']) if row['device_info_json'] else None,
    }


def create_tracking(tracking_id, label, created_at=None):
    with connection() as conn:
        conn.execute(
            'INSERT INTO tracking (id, label, created_at, status) VALUES (?, ?, ?, ?)',
            (tracking_id, label, created_at or _now(), 'pending'),
        )
    return get_tracking(tracking_id)


def get_tracking(tracking_id):
    with connection() as conn:
        row = conn.execute('SELECT * FROM tracking WHERE id = ?', (tracking_id,)).fetchone()
    return _track_from_row(row)


def list_tracking():
    with connection() as conn:
        rows = conn.execute('SELECT * FROM tracking ORDER BY created_at DESC').fetchall()
    return [(row['id'], _track_from_row(row)) for row in rows]


def update_tracking_location(tracking_id, location, device_info=None):
    device_json = json.dumps(device_info) if device_info is not None else None
    with connection() as conn:
        cursor = conn.execute(
            'UPDATE tracking SET status = ?, location_json = ?, device_info_json = ?'
            ' WHERE id = ?',
            ('success', json.dumps(location), device_json, tracking_id),
        )
        return cursor.rowcount > 0


# ── Cameras ──

def _camera_from_row(row):
    return {field: row[field] for field in CAMERA_FIELDS}


def load_cameras():
    with connection() as conn:
        rows = conn.execute('SELECT * FROM cameras').fetchall()
    return [_camera_from_row(row) for row in rows]


def get_camera(camera_id):
    with connection() as conn:
        row = conn.execute('SELECT * FROM cameras WHERE id = ?', (camera_id,)).fetchone()
    return _camera_from_row(row) if row else None


def get_cities():
    with connection() as conn:
        rows = conn.execute(
            'SELECT city, COUNT(*) AS total FROM cameras GROUP BY city ORDER BY city'
        ).fetchall()
    return {row['city'] or 'Unknown': row['total'] for row in rows}


def save_camera(camera):
    values = tuple(camera.get(field) for field in CAMERA_FIELDS)
    placeholders = ', '.join('?' for _ in CAMERA_FIELDS)
    updates = ', '.join(f'{field} = excluded.{field}' for field in CAMERA_FIELDS if field != 'id')
    with connection() as conn:
        conn.execute(
            f'INSERT INTO cameras ({", ".join(CAMERA_FIELDS)}) VALUES ({placeholders})'
            f' ON CONFLICT(id) DO UPDATE SET {updates}',
            values,
        )
    return True


def replace_cameras(cameras):
    rows = [
        tuple(cam.get(field) for field in CAMERA_FIELDS)
        for cam in cameras
        if cam.get('id')
    ]
    placeholders = ', '.join('?' for _ in CAMERA_FIELDS)
    with connection() as conn:
        conn.execute('DELETE FROM cameras')
        if rows:
            conn.executemany(
                f'INSERT INTO cameras ({", ".join(CAMERA_FIELDS)}) VALUES ({placeholders})',
                rows,
            )
    return len(rows)


# ── Provider usage ──

def record_provider_call(provider, success=True):
    with connection() as conn:
        conn.execute(
            'INSERT INTO provider_usage (provider, calls, errors, last_called_at)'
            ' VALUES (?, 1, ?, ?)'
            ' ON CONFLICT(provider) DO UPDATE SET'
            ' calls = calls + 1,'
            ' errors = errors + excluded.errors,'
            ' last_called_at = excluded.last_called_at',
            (provider, 0 if success else 1, _now()),
        )


def record_provider_cache_hit(provider):
    with connection() as conn:
        conn.execute(
            'INSERT INTO provider_usage (provider, calls, errors, cache_hits, last_called_at)'
            ' VALUES (?, 0, 0, 1, NULL)'
            ' ON CONFLICT(provider) DO UPDATE SET cache_hits = cache_hits + 1',
            (provider,),
        )


@contextmanager
def provider_call(provider):
    """Record a provider call, including failures, without swallowing errors."""
    try:
        yield
    except Exception:
        record_provider_call(provider, success=False)
        raise
    else:
        record_provider_call(provider, success=True)


def provider_usage():
    with connection() as conn:
        rows = conn.execute(
            'SELECT provider, calls, errors, cache_hits, last_called_at'
            ' FROM provider_usage ORDER BY calls DESC, provider ASC'
        ).fetchall()
    return [dict(row) for row in rows]


# ── Jobs ──
JOB_JSON_FIELDS = ('params', 'log', 'partial', 'result')


def _job_from_row(row):
    if row is None:
        return None
    job = dict(row)
    for field in JOB_JSON_FIELDS:
        raw = job.pop(f'{field}_json', None)
        job[field] = json.loads(raw) if raw else ([] if field == 'log' else None)
    return job


def create_job(job_id, kind, target, params):
    with connection() as conn:
        conn.execute(
            'INSERT INTO jobs (id, kind, target, params_json, status, progress, created_at)'
            " VALUES (?, ?, ?, ?, 'queued', 0, ?)",
            (job_id, kind, target, json.dumps(params or {}), _now()),
        )


def get_job(job_id):
    with connection() as conn:
        row = conn.execute('SELECT * FROM jobs WHERE id = ?', (job_id,)).fetchone()
    return _job_from_row(row)


def list_jobs(kind=None, limit=20):
    sql = ('SELECT id, kind, target, status, progress, message, error, created_at,'
           ' started_at, finished_at FROM jobs')
    args = []
    if kind:
        sql += ' WHERE kind = ?'
        args.append(kind)
    sql += ' ORDER BY created_at DESC, rowid DESC LIMIT ?'
    args.append(limit)
    with connection() as conn:
        return [dict(r) for r in conn.execute(sql, args).fetchall()]


def update_job(job_id, **fields):
    """Update job columns; JSON fields (log/partial/result/params) are encoded."""
    if not fields:
        return
    columns = []
    values = []
    for key, value in fields.items():
        if key in JOB_JSON_FIELDS:
            columns.append(f'{key}_json = ?')
            values.append(json.dumps(value, default=str))
        elif key in ('status', 'progress', 'message', 'error', 'started_at', 'finished_at'):
            columns.append(f'{key} = ?')
            values.append(value)
        else:
            raise ValueError(f'Unknown job field: {key}')
    values.append(job_id)
    with connection() as conn:
        conn.execute(f'UPDATE jobs SET {", ".join(columns)} WHERE id = ?', values)


def now():
    return _now()


def stats():
    with connection() as conn:
        tracking_total = conn.execute('SELECT COUNT(*) FROM tracking').fetchone()[0]
        camera_total = conn.execute('SELECT COUNT(*) FROM cameras').fetchone()[0]
        job_total = conn.execute('SELECT COUNT(*) FROM jobs').fetchone()[0]
    return {
        'job_total': job_total,
        'tracking_total': tracking_total,
        'camera_total': camera_total,
        'db_path': get_db_path(),
    }
