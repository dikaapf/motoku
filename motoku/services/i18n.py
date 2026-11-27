"""Minimal i18n (Indonesian source strings → English catalogue).

Templates call ``_('Teks Indonesia')``; when the active language is English the
string is looked up in ``translations/en.json`` (missing keys fall back to the
Indonesian source, so nothing ever renders blank). Language resolution:
``?lang=`` → ``motoku_lang`` cookie → ``Accept-Language`` → ``MOTOKU_DEFAULT_LANG``.
``scripts/i18n_check.py`` lists strings that still lack a translation.
"""

import json
import os
import re

from flask import g, redirect, request, url_for

LANGS = {'id': 'Bahasa Indonesia', 'en': 'English'}
COOKIE = 'motoku_lang'
BASE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'translations')
_catalogs = {}


def catalog(lang):
    if lang == 'id':
        return {}
    if lang not in _catalogs:
        path = os.path.join(BASE, f'{lang}.json')
        try:
            with open(path, encoding='utf-8') as fh:
                _catalogs[lang] = json.load(fh)
        except (OSError, json.JSONDecodeError):
            _catalogs[lang] = {}
    return _catalogs[lang]


def reload():
    _catalogs.clear()


def current():
    return getattr(g, 'lang', None) or os.environ.get('MOTOKU_DEFAULT_LANG', 'id')


def gettext(text, **kwargs):
    translated = catalog(current()).get(text, text) if text else text
    return translated.format(**kwargs) if kwargs else translated


def resolve_lang():
    wanted = request.args.get('lang')
    if wanted in LANGS:
        return wanted
    cookie = request.cookies.get(COOKIE)
    if cookie in LANGS:
        return cookie
    best = request.accept_languages.best_match(list(LANGS))
    return best or os.environ.get('MOTOKU_DEFAULT_LANG', 'id')


def init_app(app):
    app.jinja_env.globals.update(_=gettext, LANGS=LANGS, current_lang=current)

    @app.before_request
    def _set_lang():
        g.lang = resolve_lang()

    @app.after_request
    def _persist(response):
        wanted = request.args.get('lang')
        if wanted in LANGS:
            response.set_cookie(COOKIE, wanted, max_age=365 * 86400, samesite='Lax')
        return response

    @app.route('/lang/<code>')
    def set_language(code):
        target = request.referrer or url_for('index')
        resp = redirect(target)
        if code in LANGS:
            resp.set_cookie(COOKIE, code, max_age=365 * 86400, samesite='Lax')
        return resp


STRING_RE = re.compile(r"""_\(\s*(['"])((?:\\.|(?!\1).)+)\1""")


def extract_strings(root):
    """Collect literal strings passed to ``_()`` in templates and catalog.py."""
    found = set()
    paths = []
    for folder, _dirs, files in os.walk(os.path.join(root, 'templates')):
        paths += [os.path.join(folder, f) for f in files if f.endswith('.html')]
    paths.append(os.path.join(root, 'services', 'setup_check.py'))
    for path in paths:
        with open(path, encoding='utf-8') as fh:
            for m in STRING_RE.finditer(fh.read()):
                found.add(m.group(2).replace("\\'", "'").replace('\\"', '"'))
    from services import catalog as tool_catalog
    from services import detect
    found.update(detect.TYPE_LABELS.values())
    for routes in detect.ROUTES.values():
        found.update(label for _endpoint, label, _field in routes)
    for key, label, items in tool_catalog.CATEGORIES:
        found.add(label)
        for _endpoint, tlabel, _icon, _color, desc, _kw in items:
            found.update([tlabel, desc])
    return found
