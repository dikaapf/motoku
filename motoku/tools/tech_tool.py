from Wappalyzer import Wappalyzer, WebPage


def detect(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url)
        technologies = wappalyzer.analyze(webpage)
    except Exception as e:
        raise ValueError(f'Gagal mendeteksi teknologi: {e}')

    results = []
    for tech in sorted(technologies, key=lambda t: t.name):
        categories = ', '.join(tech.categories) if tech.categories else 'Lainnya'
        results.append({
            'name': tech.name,
            'version': tech.version or '-',
            'confidence': f"{tech.confidence}%",
            'categories': categories,
        })
    return results
