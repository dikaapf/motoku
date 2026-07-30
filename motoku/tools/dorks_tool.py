DORK_TEMPLATES = [
    {
        'category': 'File Konfigurasi & Sensitif',
        'dorks': [
            'site:{target} ext:env',
            'site:{target} ext:conf OR ext:cfg OR ext:config',
            'site:{target} ext:sql OR ext:db OR ext:sqlite',
            'site:{target} ext:log',
            'site:{target} ext:bak OR ext:backup OR ext:old',
            'site:{target} ext:yml OR ext:yaml',
            'site:{target} "DB_PASSWORD" OR "DB_USERNAME"',
            'site:{target} "-----BEGIN RSA PRIVATE KEY-----"',
        ]
    },
    {
        'category': 'Halaman Admin & Login',
        'dorks': [
            'site:{target} inurl:admin OR inurl:login OR inurl:panel',
            'site:{target} intitle:"admin" intitle:"login"',
            'site:{target} inurl:dashboard OR inurl:cpanel',
            'site:{target} inurl:wp-admin OR inurl:administrator',
        ]
    },
    {
        'category': 'Dokumen & File Publik',
        'dorks': [
            'site:{target} filetype:pdf',
            'site:{target} filetype:doc OR filetype:docx OR filetype:xls',
            'site:{target} intitle:"index of"',
            'site:{target} intitle:"index of" /etc',
            'site:{target} intitle:"index of" /backup',
        ]
    },
    {
        'category': 'Parameter & Celah',
        'dorks': [
            'site:{target} inurl:?id=',
            'site:{target} inurl:.php?id=',
            'site:{target} inurl:redirect= OR inurl:url=',
            'site:{target} inurl:file= OR inurl:page=',
            'site:{target} "error" "warning" "notice" filetype:php',
        ]
    },
    {
        'category': 'Subdomain & Path',
        'dorks': [
            'site:*.{target}',
            'site:{target} -www',
            'site:{target} inurl:dev OR inurl:staging OR inurl:test',
        ]
    },
]


def generate(target):
    target = target.strip().lower()
    if not target.startswith(('http://', 'https://')):
        target = target
    from urllib.parse import urlparse
    parsed = urlparse(target)
    clean = parsed.netloc or parsed.path
    clean = clean.split('/')[0].split(':')[0]

    results = []
    for group in DORK_TEMPLATES:
        category = group['category']
        items = []
        for template in group['dorks']:
            dork = template.replace('{target}', clean)
            url = f"https://www.google.com/search?q={dork.replace(' ', '+')}"
            items.append({'dork': dork, 'url': url})
        results.append({'category': category, 'items': items})
    return results, clean
