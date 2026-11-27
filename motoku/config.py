import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _env_bool(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ('1', 'true', 'yes', 'on')


class Config:
    """Application configuration, overridable through environment variables."""

    SECRET_KEY = os.environ.get('MOTOKU_SECRET_KEY', 'dev-only-change-me')

    HOST = os.environ.get('MOTOKU_HOST', '127.0.0.1')
    PORT = int(os.environ.get('MOTOKU_PORT', '5000'))
    DEBUG = _env_bool('MOTOKU_DEBUG', False)

    # Optional HTTP Basic authentication. When both values are set, every
    # non-static request must authenticate.
    AUTH_USER = os.environ.get('MOTOKU_AUTH_USER', '')
    AUTH_PASSWORD = os.environ.get('MOTOKU_AUTH_PASSWORD', '')

    # Request timeouts (seconds) shared by tools that make outbound calls.
    HTTP_TIMEOUT = int(os.environ.get('MOTOKU_HTTP_TIMEOUT', '10'))

    # Upload limit (image forensics).
    MAX_CONTENT_LENGTH = int(os.environ.get('MOTOKU_MAX_UPLOAD_MB', '16')) * 1024 * 1024

    # Persistence
    DB_PATH = os.environ.get('MOTOKU_DB_PATH', os.path.join(BASE_DIR, 'data', 'motoku.db'))

    # CSRF protection on state-changing requests.
    CSRF_ENABLED = _env_bool('MOTOKU_CSRF_ENABLED', True)

    # Watchlist scheduler thread (one process wins a DB lease).
    SCHEDULER_ENABLED = _env_bool('MOTOKU_SCHEDULER', True)

    # Global per-client rate limiting.
    RATE_LIMIT_ENABLED = _env_bool('MOTOKU_RATE_LIMIT_ENABLED', True)
    RATE_LIMIT_REQUESTS = int(os.environ.get('MOTOKU_RATE_LIMIT_REQUESTS', '120'))
    RATE_LIMIT_WINDOW = int(os.environ.get('MOTOKU_RATE_LIMIT_WINDOW', '60'))
