"""Provider abstraction.

Every outbound data source (HIBP, RDAP, crt.sh, ...) is declared once as a
:class:`Provider` with its cache TTL, daily quota and optional API key. Tools
call :meth:`Provider.fetch` instead of talking to ``requests`` directly so that
caching, quota enforcement and usage accounting happen in one place.
"""

import hashlib
import json
import os
from datetime import datetime, timezone

from services import cache


class QuotaExceeded(Exception):
    """Raised when a provider's daily quota has been used up."""


class ProviderUnavailable(Exception):
    """Raised when a provider needs an API key that is not configured."""


_registry = {}


class Provider:
    def __init__(self, name, *, ttl=3600, daily_quota=None, key_env=None,
                 description='', homepage=''):
        self.name = name
        self.ttl = ttl
        self.daily_quota = daily_quota
        self.key_env = key_env
        self.description = description
        self.homepage = homepage

    # ── configuration ──
    @property
    def api_key(self):
        return os.environ.get(self.key_env, '').strip() if self.key_env else ''

    @property
    def configured(self):
        return not self.key_env or bool(self.api_key)

    # ── quota ──
    def _quota_key(self):
        day = datetime.now(timezone.utc).strftime('%Y%m%d')
        return f'quota:{self.name}:{day}'

    def used_today(self):
        value = cache.get(self._quota_key())
        return int(value or 0)

    def remaining(self):
        if self.daily_quota is None:
            return None
        return max(0, self.daily_quota - self.used_today())

    def _consume(self):
        if self.daily_quota is None:
            cache.get_backend().incr(self._quota_key(), 86400)
            return
        used = cache.get_backend().incr(self._quota_key(), 86400)
        if used > self.daily_quota:
            raise QuotaExceeded(
                f'Kuota harian {self.name} habis ({self.daily_quota}/hari)'
            )

    # ── calls ──
    def cache_key(self, key):
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode()
        ).hexdigest()[:32]
        return f'prov:{self.name}:{digest}'

    def fetch(self, key, func, *, ttl=None, use_cache=True):
        """Return ``func()`` for ``key``, served from cache when possible.

        ``func`` must return a JSON-serialisable value. Exceptions propagate
        (and are counted as errors); they are never cached.
        """
        if not self.configured:
            raise ProviderUnavailable(
                f'{self.name} membutuhkan API key ({self.key_env})'
            )

        ck = self.cache_key(key)
        if use_cache:
            hit = cache.get(ck)
            if hit is not None:
                _record(self.name, cached=True)
                return hit

        self._consume()
        try:
            value = func()
        except Exception:
            _record(self.name, success=False)
            raise
        _record(self.name, success=True)

        if use_cache and value is not None:
            cache.set(ck, value, self.ttl if ttl is None else ttl)
        return value

    def status(self):
        return {
            'name': self.name,
            'description': self.description,
            'homepage': self.homepage,
            'configured': self.configured,
            'key_env': self.key_env,
            'ttl': self.ttl,
            'daily_quota': self.daily_quota,
            'used_today': self.used_today(),
            'remaining': self.remaining(),
        }


def _record(name, success=True, cached=False):
    try:
        import db

        if cached:
            db.record_provider_cache_hit(name)
        else:
            db.record_provider_call(name, success=success)
    except Exception:
        pass


def register(name, **kwargs):
    provider = Provider(name, **kwargs)
    _registry[name] = provider
    return provider


def get(name):
    return _registry[name]


def all_providers():
    return sorted(_registry.values(), key=lambda p: p.name)
