import hashlib
import requests


EMAILREP_URL = "https://emailrep.io/{email}"


def emailrep(email):
    headers = {"User-Agent": "Motoku-OSINT/1.0"}
    resp = requests.get(EMAILREP_URL.format(email=email), headers=headers, timeout=10)
    if resp.status_code == 429:
        raise ValueError("Rate limited by emailrep.io (10 req/hr without key)")
    if resp.status_code != 200:
        raise ValueError(f"emailrep.io returned {resp.status_code}")
    return resp.json()


def gravatar(email):
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/{h}.json"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            entry = data.get('entry', [{}])[0]
            return {
                'profile_url': f"https://www.gravatar.com/{h}",
                'display_name': entry.get('displayName', ''),
                'avatar': f"https://www.gravatar.com/avatar/{h}?s=200",
                'about': entry.get('aboutMe', ''),
            }
    except Exception:
        pass
    return None
