import sys
import os
import re
import requests

SHERLOCK_DIR = '/tmp/sherlock'
sys.path.insert(0, SHERLOCK_DIR)


def sherlock_search(username, timeout=30):
    results = []
    try:
        from sherlock_project.sherlock import sherlock as sherlock_func
        from sherlock_project.sites import SitesInformation
        from sherlock_project.notify import QueryNotify
        from sherlock_project.result import QueryStatus

        sites = SitesInformation()
        site_data = {site.name: site.information for site in sites}
        query_notify = QueryNotify()
        raw = sherlock_func(username, site_data, query_notify, timeout=timeout)
    except Exception as e:
        return {'error': str(e), 'found': [], 'total_checked': 0, 'total_found': 0}

    from sherlock_project.result import QueryResult

    total_checked = len(raw)
    total_found = 0
    found = []
    for site_name, data in raw.items():
        qresult = data.get('status')
        if isinstance(qresult, QueryResult):
            status_obj = qresult.status
        elif isinstance(qresult, QueryStatus):
            status_obj = qresult
        else:
            status_obj = QueryStatus.UNKNOWN

        status_str = status_obj.value if hasattr(status_obj, 'value') else str(status_obj)

        entry = {
            'platform': site_name,
            'url': data.get('url_user', ''),
            'url_main': data.get('url_main', ''),
            'status': status_str,
            'http_status': data.get('http_status'),
        }
        results.append(entry)
        if status_str == QueryStatus.CLAIMED.value:
            total_found += 1
            found.append(entry)

    return {
        'username': username,
        'total_checked': total_checked,
        'total_found': total_found,
        'found': found,
        'all': results,
    }


def instagram_analysis(username):
    result = {
        'username': username,
        'found': False,
        'error': None,
        'bio': '',
        'full_name': '',
        'followers': 0,
        'following': 0,
        'posts': 0,
        'is_private': False,
        'is_verified': False,
        'profile_pic_url': '',
        'external_url': '',
    }
    try:
        import instaloader
        L = instaloader.Instaloader()
        profile = instaloader.Profile.from_username(L.context, username)
        result['found'] = True
        result['bio'] = profile.biography or ''
        result['full_name'] = profile.full_name or ''
        result['followers'] = profile.followers
        result['following'] = profile.followees
        result['posts'] = profile.mediacount
        result['is_private'] = profile.is_private
        result['is_verified'] = profile.is_verified
        result['profile_pic_url'] = profile.profile_pic_url or ''
        result['external_url'] = profile.external_url or ''
    except instaloader.exceptions.ProfileNotExistsException:
        result['found'] = False
    except Exception as e:
        result['error'] = str(e)
    return result


def profile_preview(url, timeout=8):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        resp = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        if resp.status_code != 200:
            return None
        html = resp.text

        title = ''
        match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if match:
            title = match.group(1).strip()[:200]

        description = ''
        match = re.search(r'<meta\s+name=["\']description["\']\s+content=["\'](.*?)["\']', html, re.IGNORECASE)
        if match:
            description = match.group(1).strip()[:300]

        og_image = ''
        match = re.search(r'<meta\s+property=["\']og:image["\']\s+content=["\'](.*?)["\']', html, re.IGNORECASE)
        if match:
            og_image = match.group(1).strip()

        return {
            'title': title,
            'description': description,
            'og_image': og_image,
            'final_url': resp.url,
        }
    except Exception:
        return None
