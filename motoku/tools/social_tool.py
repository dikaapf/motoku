"""Public social-profile lookups through official/public APIs:
GitHub, Reddit (OAuth app), Mastodon/fediverse, Bluesky, Telegram (public
t.me page) and TikTok (public profile page, best-effort)."""

import html
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor

import requests

from services.providers import ProviderUnavailable
from services.providers import registry as R

UA = {'User-Agent': 'Motoku-OSINT/1.4'}
BROWSER_UA = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) '
                            'Chrome/124.0 Safari/537.36', 'Accept-Language': 'en-US,en;q=0.8'}
MASTODON_INSTANCES = ['mastodon.social', 'mastodon.online', 'mstdn.social', 'fosstodon.org',
                      'infosec.exchange', 'mas.to', 'mastodon.world']
USERNAME_RE = re.compile(r'^@?[A-Za-z0-9._\-]{1,64}(@[A-Za-z0-9.\-]+\.[a-z]{2,})?$')


class NotFound(Exception):
    pass


def _profile(platform, **fields):
    base = {'platform': platform, 'found': True}
    base.update(fields)
    return base


def github(username):
    def run():
        headers = dict(UA)
        if R.GITHUB_PUBLIC.has_key:
            headers['Authorization'] = f'Bearer {R.GITHUB_PUBLIC.api_key}'
        resp = requests.get(f'https://api.github.com/users/{username}', headers=headers, timeout=15)
        if resp.status_code == 404:
            return None
        if resp.status_code == 403:
            raise ValueError('Rate limit GitHub (60/jam tanpa token)')
        resp.raise_for_status()
        u = resp.json()
        orgs = []
        try:
            o = requests.get(u['organizations_url'], headers=headers, timeout=10)
            if o.ok:
                orgs = [x['login'] for x in o.json()][:10]
        except requests.RequestException:
            pass
        return _profile('GitHub', username=u['login'], name=u.get('name'), bio=u.get('bio'),
                        avatar=u.get('avatar_url'), url=u.get('html_url'), location=u.get('location'),
                        company=u.get('company'), blog=u.get('blog'), email=u.get('email'),
                        twitter=u.get('twitter_username'), created=(u.get('created_at') or '')[:10],
                        stats={'followers': u.get('followers'), 'following': u.get('following'),
                               'repos': u.get('public_repos'), 'gists': u.get('public_gists')},
                        extra={'organizations': orgs, 'hireable': u.get('hireable')})
    return R.GITHUB_PUBLIC.fetch(username.lower(), run)


_reddit_token = {}


def _reddit_auth():
    client_id = os.environ.get('MOTOKU_REDDIT_CLIENT_ID', '').strip()
    if not client_id or not R.REDDIT.api_key:
        raise ProviderUnavailable('Set MOTOKU_REDDIT_CLIENT_ID dan MOTOKU_REDDIT_CLIENT_SECRET')
    import time
    if _reddit_token.get('exp', 0) > time.time() + 60:
        return _reddit_token['token']
    resp = requests.post('https://www.reddit.com/api/v1/access_token', data={'grant_type': 'client_credentials'},
                         auth=(client_id, R.REDDIT.api_key), headers={'User-Agent': 'web:motoku-osint:1.4'},
                         timeout=15)
    resp.raise_for_status()
    data = resp.json()
    _reddit_token.update(token=data['access_token'], exp=time.time() + data.get('expires_in', 3600))
    return data['access_token']


def reddit(username):
    def run():
        token = _reddit_auth()
        resp = requests.get(f'https://oauth.reddit.com/user/{username}/about',
                            headers={'Authorization': f'Bearer {token}', 'User-Agent': 'web:motoku-osint:1.4'},
                            timeout=15)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        d = resp.json().get('data', {})
        if d.get('is_suspended'):
            return _profile('Reddit', username=d.get('name'), url=f'https://www.reddit.com/user/{username}',
                            bio='Akun disuspend', stats={})
        import datetime
        created = datetime.datetime.utcfromtimestamp(d['created_utc']).strftime('%Y-%m-%d') if d.get('created_utc') else None
        return _profile('Reddit', username=d.get('name'), name=(d.get('subreddit') or {}).get('title'),
                        bio=(d.get('subreddit') or {}).get('public_description'),
                        avatar=html.unescape(d.get('icon_img') or '').split('?')[0] or None,
                        url=f'https://www.reddit.com/user/{d.get("name")}', created=created,
                        stats={'karma_post': d.get('link_karma'), 'karma_comment': d.get('comment_karma')},
                        extra={'verified_email': d.get('has_verified_email'), 'employee': d.get('is_employee')})
    return R.REDDIT.fetch(username.lower(), run)


def _strip_html(text):
    return re.sub(r'\s+', ' ', html.unescape(re.sub(r'<[^>]+>', ' ', text or ''))).strip()


def mastodon(username):
    """``user@instance`` is looked up directly; a bare name is tried on popular instances."""
    if '@' in username.strip('@'):
        user, instance = username.strip('@').split('@', 1)
        targets = [(user, instance)]
    else:
        targets = [(username, inst) for inst in MASTODON_INSTANCES]

    def lookup(user, instance):
        resp = requests.get(f'https://{instance}/api/v1/accounts/lookup', params={'acct': user},
                            headers=UA, timeout=10)
        if resp.status_code != 200:
            return None
        a = resp.json()
        return _profile('Mastodon', username=f'{a["acct"]}@{instance}' if '@' not in a['acct'] else a['acct'],
                        name=a.get('display_name'), bio=_strip_html(a.get('note')), avatar=a.get('avatar'),
                        url=a.get('url'), created=(a.get('created_at') or '')[:10],
                        stats={'followers': a.get('followers_count'), 'following': a.get('following_count'),
                               'posts': a.get('statuses_count')},
                        extra={'fields': [{'name': f['name'], 'value': _strip_html(f['value']),
                                           'verified': bool(f.get('verified_at'))} for f in a.get('fields', [])],
                               'bot': a.get('bot'), 'last_status': a.get('last_status_at')})

    def run():
        with ThreadPoolExecutor(max_workers=len(targets)) as pool:
            hits = [h for h in pool.map(lambda t: _safe(lookup, *t), targets) if h]
        return hits
    return R.MASTODON.fetch(username.lower(), run)


def _safe(func, *args):
    try:
        return func(*args)
    except Exception:
        return None


def bluesky(username):
    handle = username.strip('@')
    if '.' not in handle:
        handle = f'{handle}.bsky.social'

    def run():
        resp = requests.get('https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile',
                            params={'actor': handle}, headers=UA, timeout=15)
        if resp.status_code == 400:
            return None
        resp.raise_for_status()
        p = resp.json()
        return _profile('Bluesky', username=p.get('handle'), name=p.get('displayName'), bio=p.get('description'),
                        avatar=p.get('avatar'), url=f'https://bsky.app/profile/{p.get("handle")}',
                        created=(p.get('createdAt') or '')[:10],
                        stats={'followers': p.get('followersCount'), 'following': p.get('followsCount'),
                               'posts': p.get('postsCount')},
                        extra={'did': p.get('did')})
    return R.BLUESKY.fetch(handle.lower(), run)


def _og(page, prop):
    m = re.search(rf'<meta property="og:{prop}" content="([^"]*)"', page)
    return html.unescape(m.group(1)) if m else None


def telegram(username):
    user = username.strip('@')

    def run():
        resp = requests.get(f'https://t.me/{user}', headers=BROWSER_UA, timeout=15)
        resp.raise_for_status()
        page = resp.text
        title = _og(page, 'title') or ''
        # Unknown usernames render a generic "Telegram: Contact @x" page without a profile photo.
        if 'tgme_page_photo' not in page and 'tgme_page_extra' not in page:
            return None
        extra = re.search(r'tgme_page_extra">([^<]*)', page)
        extra_text = html.unescape(extra.group(1)).strip() if extra else ''
        kind = 'channel/grup' if re.search(r'(subscribers|members|online)', extra_text) else 'user/bot'
        return _profile('Telegram', username=user, name=title.replace('Telegram: Contact @', '') or None,
                        bio=_og(page, 'description'), avatar=_og(page, 'image'), url=f'https://t.me/{user}',
                        stats={'info': extra_text} if extra_text else {}, extra={'type': kind})
    return R.TELEGRAM.fetch(user.lower(), run)


def tiktok(username):
    user = username.strip('@')

    def run():
        resp = requests.get(f'https://www.tiktok.com/@{user}', headers=BROWSER_UA, timeout=20)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        m = re.search(r'<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>', resp.text, re.S)
        if not m:
            raise ValueError('Struktur halaman TikTok berubah atau diblokir')
        data = json.loads(m.group(1))
        detail = data.get('__DEFAULT_SCOPE__', {}).get('webapp.user-detail', {})
        if detail.get('statusCode') not in (0, None) or not detail.get('userInfo'):
            return None
        u, st = detail['userInfo']['user'], detail['userInfo'].get('stats', {})
        return _profile('TikTok', username=u.get('uniqueId'), name=u.get('nickname'), bio=u.get('signature'),
                        avatar=u.get('avatarMedium'), url=f'https://www.tiktok.com/@{u.get("uniqueId")}',
                        stats={'followers': st.get('followerCount'), 'following': st.get('followingCount'),
                               'likes': st.get('heartCount'), 'videos': st.get('videoCount')},
                        extra={'verified': u.get('verified'), 'private': u.get('privateAccount'),
                               'region': u.get('region'), 'bio_link': (u.get('bioLink') or {}).get('link')})
    return R.TIKTOK.fetch(user.lower(), run)


PLATFORMS = {'github': github, 'reddit': reddit, 'mastodon': mastodon, 'bluesky': bluesky,
             'telegram': telegram, 'tiktok': tiktok}


def lookup(username, platforms=None):
    username = (username or '').strip()
    if not USERNAME_RE.match(username):
        raise ValueError('Username tidak valid')
    username = username.lstrip('@')  # '@alice' → 'alice'; 'alice@instance' stays intact
    names = [p for p in (platforms or PLATFORMS) if p in PLATFORMS]

    def run(platform):
        try:
            value = PLATFORMS[platform](username)
        except ProviderUnavailable as e:
            return {'platform': platform, 'status': 'no_key', 'message': str(e), 'profiles': []}
        except Exception as e:
            return {'platform': platform, 'status': 'error', 'message': str(e)[:200], 'profiles': []}
        if value is None:
            return {'platform': platform, 'status': 'not_found', 'profiles': []}
        profiles = value if isinstance(value, list) else [value]
        return {'platform': platform, 'status': 'ok' if profiles else 'not_found', 'profiles': profiles}

    with ThreadPoolExecutor(max_workers=len(names) or 1) as pool:
        results = list(pool.map(run, names))
    order = {'ok': 0, 'not_found': 1, 'no_key': 2, 'error': 3}
    results.sort(key=lambda r: order.get(r['status'], 9))
    found = [p for r in results for p in r['profiles']]
    return {'username': username, 'results': results, 'found': len(found),
            'pivots': _pivots(found)}


def _pivots(profiles):
    """Collect cross-platform leads (links, emails, other handles) from profiles."""
    leads = []
    for p in profiles:
        src = f'{p["platform"]} ({p.get("username")})'
        for key in ('blog', 'email', 'twitter', 'company', 'location'):
            if p.get(key):
                leads.append({'source': src, 'kind': key, 'value': str(p[key])})
        for f in (p.get('extra') or {}).get('fields', []) or []:
            leads.append({'source': src, 'kind': f['name'], 'value': f['value']})
        if (p.get('extra') or {}).get('bio_link'):
            leads.append({'source': src, 'kind': 'link', 'value': p['extra']['bio_link']})
        for url in re.findall(r'https?://\S+', p.get('bio') or ''):
            leads.append({'source': src, 'kind': 'link', 'value': url.rstrip('.,)')})
    unique = {(lead['source'], lead['kind'], lead['value']): lead for lead in leads}
    return list(unique.values())
