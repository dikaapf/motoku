"""Pluggable result cache.

Uses Redis when ``MOTOKU_REDIS_URL`` is set and reachable, otherwise falls back
to a process-local TTL cache so the app keeps working without extra services.
Values must be JSON-serialisable.
"""

import json
import os
import threading
import time

_backend = None
_lock = threading.Lock()


class MemoryCache:
    name = 'memory'

    def __init__(self, max_items=2048):
        self._data = {}
        self._max = max_items
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            expires, value = item
            if expires and expires < time.time():
                self._data.pop(key, None)
                return None
            return value

    def set(self, key, value, ttl):
        with self._lock:
            if len(self._data) >= self._max:
                # Drop the entry closest to expiry; cheap and good enough.
                oldest = min(self._data, key=lambda k: self._data[k][0] or 0)
                self._data.pop(oldest, None)
            self._data[key] = (time.time() + ttl if ttl else 0, value)

    def delete(self, key):
        with self._lock:
            self._data.pop(key, None)

    def incr(self, key, ttl):
        with self._lock:
            expires, value = self._data.get(key, (0, 0))
            if expires and expires < time.time():
                value = 0
                expires = 0
            value += 1
            self._data[key] = (expires or (time.time() + ttl if ttl else 0), value)
            return value

    def clear(self):
        with self._lock:
            self._data.clear()

    def info(self):
        with self._lock:
            return {'backend': self.name, 'keys': len(self._data)}


class RedisCache:
    name = 'redis'

    def __init__(self, client, prefix='motoku:'):
        self._r = client
        self._prefix = prefix

    def _k(self, key):
        return self._prefix + key

    def get(self, key):
        raw = self._r.get(self._k(key))
        return json.loads(raw) if raw is not None else None

    def set(self, key, value, ttl):
        self._r.set(self._k(key), json.dumps(value, default=str), ex=ttl or None)

    def delete(self, key):
        self._r.delete(self._k(key))

    def incr(self, key, ttl):
        k = self._k(key)
        value = self._r.incr(k)
        if value == 1 and ttl:
            self._r.expire(k, ttl)
        return value

    def clear(self):
        for k in self._r.scan_iter(self._prefix + '*'):
            self._r.delete(k)

    def info(self):
        try:
            keys = sum(1 for _ in self._r.scan_iter(self._prefix + '*'))
        except Exception:
            keys = None
        return {'backend': self.name, 'keys': keys}


def _build_backend():
    url = os.environ.get('MOTOKU_REDIS_URL', '').strip()
    if url:
        try:
            import redis

            client = redis.Redis.from_url(url, socket_timeout=2, socket_connect_timeout=2)
            client.ping()
            return RedisCache(client)
        except Exception:
            pass
    return MemoryCache()


def get_backend():
    global _backend
    if _backend is None:
        with _lock:
            if _backend is None:
                _backend = _build_backend()
    return _backend


def set_backend(backend):
    """Replace the backend (used by tests and app configuration)."""
    global _backend
    with _lock:
        _backend = backend


def get(key):
    try:
        return get_backend().get(key)
    except Exception:
        return None


def set(key, value, ttl=3600):  # noqa: A001 - mirrors cache API naming
    try:
        get_backend().set(key, value, ttl)
    except Exception:
        pass


def info():
    try:
        return get_backend().info()
    except Exception as e:
        return {'backend': 'error', 'error': str(e)}
