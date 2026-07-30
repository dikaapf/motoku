SEARCH_ENGINES = [
    {
        'id': 'google',
        'name': 'Google',
        'url': 'https://www.google.com/search?q={query}',
        'icon': 'bi-google',
        'color': 'text-success',
        'border': 'border-success',
    },
    {
        'id': 'bing',
        'name': 'Bing',
        'url': 'https://www.bing.com/search?q={query}',
        'icon': 'bi-microsoft',
        'color': 'text-primary',
        'border': 'border-primary',
    },
    {
        'id': 'duckduckgo',
        'name': 'DuckDuckGo',
        'url': 'https://duckduckgo.com/?q={query}',
        'icon': 'bi-shield-check',
        'color': 'text-warning',
        'border': 'border-warning',
    },
    {
        'id': 'yahoo',
        'name': 'Yahoo',
        'url': 'https://search.yahoo.com/search?p={query}',
        'icon': 'bi-search',
        'color': 'text-danger',
        'border': 'border-danger',
    },
    {
        'id': 'yandex',
        'name': 'Yandex',
        'url': 'https://yandex.com/search/?text={query}',
        'icon': 'bi-globe2',
        'color': 'text-info',
        'border': 'border-info',
    },
    {
        'id': 'brave',
        'name': 'Brave',
        'url': 'https://search.brave.com/search?q={query}',
        'icon': 'bi-shield-fill',
        'color': 'text-warning',
        'border': 'border-warning',
    },
    {
        'id': 'ask',
        'name': 'Ask.com',
        'url': 'https://www.ask.com/web?q={query}',
        'icon': 'bi-question-circle',
        'color': 'text-secondary',
        'border': 'border-secondary',
    },
    {
        'id': 'startpage',
        'name': 'StartPage',
        'url': 'https://www.startpage.com/do/dsearch?query={query}',
        'icon': 'bi-incognito',
        'color': 'text-info',
        'border': 'border-info',
    },
]


def generate_links(name, selected_ids=None):
    from urllib.parse import quote
    query = quote(name.strip())
    results = []
    for engine in SEARCH_ENGINES:
        if selected_ids and engine['id'] not in selected_ids:
            continue
        search_url = engine['url'].replace('{query}', query)
        results.append({
            'id': engine['id'],
            'name': engine['name'],
            'url': search_url,
            'icon': engine['icon'],
            'color': engine['color'],
            'border': engine['border'],
        })
    return results


def fetch_results(name, max_results=8):
    import requests

    headers = {
        'User-Agent': 'MotokuOSINT/1.0',
    }

    params = {
        'action': 'query',
        'list': 'search',
        'srsearch': name.strip(),
        'format': 'json',
        'srlimit': max_results,
    }

    try:
        resp = requests.get('https://en.wikipedia.org/w/api.php',
                            params=params, headers=headers, timeout=15)
        data = resp.json()
        items = []
        for result in data.get('query', {}).get('search', []):
            title = result.get('title', '')
            snippet = result.get('snippet', '')
            snippet = snippet.replace('<span class="searchmatch">', '').replace('</span>', '')
            page_url = f"https://en.wikipedia.org/wiki/{title.replace(' ', '_')}"
            items.append({
                'title': title,
                'url': page_url,
                'snippet': snippet,
            })
        return items
    except:
        return []
