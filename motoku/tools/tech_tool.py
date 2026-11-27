from Wappalyzer import Wappalyzer, WebPage

from db import provider_call


def detect(url):
    """Detect technologies used by a website.

    Uses python-Wappalyzer's versioned+categorised API, which returns a dict:
        {tech_name: {'versions': [...], 'categories': [...]}}
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        wappalyzer = Wappalyzer.latest()
        with provider_call('wappalyzer'):
            webpage = WebPage.new_from_url(url, timeout=15)
            technologies = wappalyzer.analyze_with_versions_and_categories(webpage)
    except Exception as e:
        raise ValueError(f'Gagal mendeteksi teknologi: {e}')

    results = []
    for name in sorted(technologies):
        info = technologies[name] or {}
        versions = [v for v in (info.get('versions') or []) if v]
        categories = info.get('categories') or []

        confidence = wappalyzer.get_confidence(name)
        if not isinstance(confidence, (int, float)):
            confidence = None
        else:
            confidence = min(int(confidence), 100)

        results.append({
            'name': name,
            'version': ', '.join(versions) if versions else '-',
            'confidence': f'{confidence}%' if confidence is not None else '-',
            'categories': ', '.join(categories) if categories else 'Lainnya',
        })
    return results
