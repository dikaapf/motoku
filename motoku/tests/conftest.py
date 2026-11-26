import pytest

from app import app as flask_app


@pytest.fixture(autouse=True)
def isolated_runtime(tmp_path, monkeypatch):
    import db
    import rate_limit
    from services import cache

    db.configure(str(tmp_path / 'test.db'), migrate=False)
    rate_limit.reset()
    cache.set_backend(cache.MemoryCache())
    monkeypatch.delenv('MOTOKU_HIBP_API_KEY', raising=False)
    monkeypatch.setenv('MOTOKU_JOB_BACKEND', 'inline')
    flask_app.config.update(
        TESTING=True,
        CSRF_ENABLED=False,
        RATE_LIMIT_ENABLED=False,
        DB_PATH=str(tmp_path / 'test.db'),
    )
    yield
    rate_limit.reset()


@pytest.fixture
def client():
    with flask_app.test_client() as test_client:
        yield test_client
