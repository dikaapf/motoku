"""Background job queue.

Long-running scans (subdomain enumeration, port scans, full recon) run as jobs.
Job state, progress, logs and results live in the SQLite ``jobs`` table, so any
web worker can report on any job (e.g. via Server-Sent Events).

Two execution backends:

* ``thread`` (default): a process-local thread pool. Zero setup.
* ``inline``: run synchronously inside the request (tests, debugging).
* ``rq``: Redis Queue. Set ``MOTOKU_JOB_BACKEND=rq`` and ``MOTOKU_REDIS_URL``,
  then run ``rq worker motoku`` (docker-compose ships a ``worker`` service).
"""

import logging
import os
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor

import db

log = logging.getLogger(__name__)

QUEUE_NAME = 'motoku'
MAX_LOG_LINES = 200
FINAL_STATES = ('finished', 'failed')

_handlers = {}
_executor = None
_executor_lock = threading.Lock()


class JobCancelled(Exception):
    pass


def handler(kind, label=None):
    """Register ``func(ctx, **params)`` as the implementation of ``kind``."""
    def decorator(func):
        _handlers[kind] = {'func': func, 'label': label or kind}
        return func
    return decorator


def handlers():
    return dict(_handlers)


class JobContext:
    """Passed to job handlers for progress reporting."""

    def __init__(self, job_id):
        self.job_id = job_id
        self._log = []
        self._partial = {}
        self._last_flush = 0.0
        self._lock = threading.Lock()

    def progress(self, percent, message=None):
        fields = {'progress': max(0, min(100, int(percent)))}
        if message:
            fields['message'] = message
            self._append_log(message)
            fields['log'] = list(self._log)
        db.update_job(self.job_id, **fields)

    def log(self, message):
        self._append_log(message)
        self._flush(force=False)

    def partial(self, key, value):
        """Publish an intermediate result (shown while the job is running)."""
        with self._lock:
            self._partial[key] = value
        self._flush(force=True)

    def _append_log(self, message):
        with self._lock:
            self._log.append(f'{time.strftime("%H:%M:%S")} {message}')
            del self._log[:-MAX_LOG_LINES]

    def _flush(self, force):
        now = time.monotonic()
        if not force and now - self._last_flush < 1.0:
            return
        self._last_flush = now
        with self._lock:
            db.update_job(self.job_id, log=list(self._log), partial=dict(self._partial))


def backend_name():
    return os.environ.get('MOTOKU_JOB_BACKEND', 'thread').strip().lower() or 'thread'


def _thread_executor():
    global _executor
    if _executor is None:
        with _executor_lock:
            if _executor is None:
                workers = int(os.environ.get('MOTOKU_JOB_WORKERS', '4'))
                _executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='motoku-job')
    return _executor


def _rq_queue():
    import redis
    from rq import Queue

    url = os.environ.get('MOTOKU_REDIS_URL', '').strip()
    if not url:
        raise RuntimeError('MOTOKU_JOB_BACKEND=rq membutuhkan MOTOKU_REDIS_URL')
    return Queue(QUEUE_NAME, connection=redis.Redis.from_url(url))


def enqueue(kind, target, params=None, *, run_inline=False):
    """Create a job and schedule it. Returns the job id."""
    if kind not in _handlers:
        raise ValueError(f'Jenis job tidak dikenal: {kind}')
    job_id = uuid.uuid4().hex[:12]
    db.create_job(job_id, kind, target, params or {})

    if run_inline or backend_name() == 'inline':
        run_job(job_id)
    elif backend_name() == 'rq':
        timeout = int(os.environ.get('MOTOKU_JOB_TIMEOUT', '1800'))
        _rq_queue().enqueue('services.jobs.run_job', job_id, job_timeout=timeout,
                            job_id=f'motoku-{job_id}')
    else:
        _thread_executor().submit(run_job, job_id)
    return job_id


def run_job(job_id):
    """Execute a job synchronously (called by the thread pool or an RQ worker)."""
    _ensure_handlers_loaded()
    job = db.get_job(job_id)
    if job is None:
        return
    entry = _handlers.get(job['kind'])
    if entry is None:
        db.update_job(job_id, status='failed', error=f'Handler {job["kind"]} tidak ada',
                      finished_at=db.now())
        return

    ctx = JobContext(job_id)
    db.update_job(job_id, status='running', started_at=db.now(), progress=0)
    try:
        result = entry['func'](ctx, **(job['params'] or {}))
    except Exception as e:
        log.exception('Job %s failed', job_id)
        ctx.log(f'Gagal: {e}')
        db.update_job(job_id, status='failed', error=str(e) or type(e).__name__,
                      message='Gagal', finished_at=db.now(),
                      log=ctx._log + [traceback.format_exc(limit=3)[-500:]])
        return
    db.update_job(job_id, status='finished', progress=100, message='Selesai',
                  result=result, partial={}, log=ctx._log, finished_at=db.now())


def recover_stale(max_age_s=None):
    """Mark jobs stuck in queued/running longer than the job timeout as failed.

    Happens when a process dies mid-job (restart, crash, OOM). Returns the count.
    """
    from datetime import datetime, timedelta
    max_age_s = max_age_s or int(os.environ.get('MOTOKU_JOB_TIMEOUT', '1800'))
    cutoff = (datetime.now() - timedelta(seconds=max_age_s)).strftime('%Y-%m-%d %H:%M:%S')
    with db.connection() as conn:
        cur = conn.execute(
            "UPDATE jobs SET status = 'failed', error = ?, message = 'Gagal', finished_at = ?"
            " WHERE status IN ('queued', 'running') AND COALESCE(started_at, created_at) < ?",
            ('Terhenti: proses worker berhenti atau melewati batas waktu', db.now(), cutoff))
        return cur.rowcount


def get(job_id):
    return db.get_job(job_id)


def public_view(job, include_result=False):
    """Serializable snapshot used by the JSON and SSE endpoints."""
    view = {k: job.get(k) for k in ('id', 'kind', 'target', 'status', 'progress', 'message',
                                     'error', 'created_at', 'started_at', 'finished_at')}
    view['log'] = (job.get('log') or [])[-30:]
    view['partial'] = job.get('partial') or {}
    view['label'] = _handlers.get(job['kind'], {}).get('label', job['kind'])
    if include_result:
        view['result'] = job.get('result')
    return view


def _ensure_handlers_loaded():
    # Importing the module registers every handler; needed in RQ workers,
    # which import only this module.
    if not _handlers:
        import services.job_handlers  # noqa: F401
