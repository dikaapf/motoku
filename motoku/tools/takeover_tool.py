"""Subdomain takeover detection.

A host is flagged when its CNAME points at a third-party service known to be
claimable (fingerprints adapted from the community project
"can-i-take-over-xyz") and either the CNAME target no longer resolves or the
service answers with its "unclaimed resource" page.
"""

import requests

from services import resolver

# service, CNAME suffixes, HTTP body fingerprint, NXDOMAIN of target is enough
FINGERPRINTS = [
    ('AWS S3', ('.s3.amazonaws.com', '.s3-website', 's3.amazonaws.com'), 'NoSuchBucket', False),
    ('GitHub Pages', ('.github.io',), "There isn't a GitHub Pages site here", False),
    ('Heroku', ('.herokuapp.com', '.herokudns.com', '.herokussl.com'), 'No such app', True),
    ('Azure', ('.azurewebsites.net', '.cloudapp.net', '.cloudapp.azure.com', '.trafficmanager.net',
               '.blob.core.windows.net', '.azureedge.net', '.azure-api.net', '.azurefd.net'),
     None, True),
    ('Shopify', ('.myshopify.com',), 'Sorry, this shop is currently unavailable', False),
    ('Fastly', ('.fastly.net',), 'Fastly error: unknown domain', False),
    ('Pantheon', ('.pantheonsite.io',), 'The gods are wise', False),
    ('Tumblr', ('domains.tumblr.com',), "Whatever you were looking for doesn't currently exist", False),
    ('WordPress.com', ('.wordpress.com',), 'Do you want to register', False),
    ('Ghost', ('.ghost.io',), 'Domain error', False),
    ('Surge.sh', ('.surge.sh',), 'project not found', False),
    ('Bitbucket', ('.bitbucket.io',), 'Repository not found', False),
    ('Netlify', ('.netlify.app', '.netlify.com'), 'Not Found - Request ID', False),
    ('Vercel', ('.vercel.app', '.now.sh'), 'The deployment could not be found', False),
    ('Zendesk', ('.zendesk.com',), 'Help Center Closed', False),
    ('Readme.io', ('.readme.io',), 'Project doesnt exist... yet!', False),
    ('Webflow', ('proxy.webflow.com', 'proxy-ssl.webflow.com'), 'The page you are looking for doesn', False),
    ('Cargo', ('.cargocollective.com',), '404 Not Found', False),
    ('Unbounce', ('unbouncepages.com',), 'The requested URL was not found on this server', False),
    ('Helpscout', ('.helpscoutdocs.com',), 'No settings were found for this company', False),
    ('Strikingly', ('.s.strikinglydns.com',), 'page not found', False),
    ('Fly.io', ('.fly.dev', '.edgeapp.net'), '404 Not Found', True),
    ('Agile CRM', ('.agilecrm.com',), 'Sorry, this page is no longer available', False),
    ('Elastic Beanstalk', ('.elasticbeanstalk.com',), None, True),
    ('Google Cloud Storage', ('c.storage.googleapis.com',), 'NoSuchBucket', False),
]


def match_service(cname):
    cname = cname.lower().rstrip('.')
    for service, suffixes, body, nx_ok in FINGERPRINTS:
        if any(cname.endswith(s) or s in cname for s in suffixes):
            return service, body, nx_ok
    return None


def check_host(host, cnames, timeout=8):
    """Return a finding dict or ``None``."""
    for cname in cnames:
        matched = match_service(cname)
        if not matched:
            continue
        service, body_fp, nx_ok = matched
        target_resolves = bool(resolver.resolve(cname, 'A') or resolver.resolve(cname, 'AAAA'))
        evidence = []
        if not target_resolves:
            evidence.append(f'CNAME target {cname} tidak resolve (NXDOMAIN)')
        body_hit = False
        if body_fp:
            for scheme in ('https', 'http'):
                try:
                    resp = requests.get(f'{scheme}://{host}', timeout=timeout, allow_redirects=True,
                                        verify=False, headers={'User-Agent': 'Motoku-OSINT/1.2'})
                    if body_fp.lower() in resp.text[:200_000].lower():
                        body_hit = True
                        evidence.append(f'Fingerprint "{body_fp}" pada {scheme}://{host}')
                    break
                except requests.RequestException:
                    continue
        vulnerable = body_hit or (nx_ok and not target_resolves)
        if vulnerable or not target_resolves:
            return {
                'host': host,
                'cname': cname,
                'service': service,
                'status': 'vulnerable' if vulnerable else 'dangling',
                'evidence': evidence,
            }
    return None


def scan(hosts, progress=None, workers=16):
    """``hosts`` is the list produced by ``subdomain_tool.enumerate``."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    candidates = [h for h in hosts if h.get('cname') and any(match_service(c) for c in h['cname'])]
    findings = []
    if not candidates:
        return {'checked': 0, 'findings': []}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(check_host, h['name'], h['cname']) for h in candidates]
        for i, fut in enumerate(as_completed(futures), 1):
            try:
                result = fut.result()
            except Exception:
                result = None
            if result:
                findings.append(result)
            if progress:
                progress(i, len(candidates))
    findings.sort(key=lambda f: (f['status'] != 'vulnerable', f['host']))
    return {'checked': len(candidates), 'findings': findings}
