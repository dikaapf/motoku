"""Flask blueprints (S5+). Older routes still live in app.py."""


def current_actor():
    from flask import g, request
    token = getattr(g, 'api_token', None)
    if token:
        return f'api:{token["name"]}'
    auth = request.authorization
    if auth and auth.username:
        return auth.username
    return 'web'
