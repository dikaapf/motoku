"""Corporate & academic lookup: GLEIF LEI, OpenCorporates, ORCID, OpenAlex,
plus links to Indonesian registries (AHU, OSS) that have no public API."""

import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

import requests

from services.providers import ProviderUnavailable
from services.providers import registry as R

UA = {'User-Agent': 'Motoku-OSINT/1.4', 'Accept': 'application/json'}
LEI_RE = re.compile(r'^[A-Z0-9]{18}[0-9]{2}$')


def _addr(a):
    if not a:
        return ''
    lines = ', '.join(x for x in a.get('addressLines', []) if x)
    return ', '.join(x for x in [lines, a.get('city'), a.get('postalCode'), a.get('country')] if x)


def gleif(query, size=10):
    q = query.strip()

    def run():
        if LEI_RE.match(q.upper()):
            resp = requests.get(f'https://api.gleif.org/api/v1/lei-records/{q.upper()}', headers=UA, timeout=20)
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
            rows = [resp.json()['data']]
        else:
            resp = requests.get('https://api.gleif.org/api/v1/lei-records', headers=UA, timeout=20, params={
                'filter[fulltext]': q, 'page[size]': size})
            resp.raise_for_status()
            rows = resp.json().get('data', [])
        out = []
        for d in rows:
            a, e = d['attributes'], d['attributes']['entity']
            out.append({
                'lei': a['lei'], 'name': e['legalName']['name'],
                'other_names': [n['name'] for n in e.get('otherNames', [])][:5],
                'status': e.get('status'), 'jurisdiction': e.get('jurisdiction'),
                'registered_as': e.get('registeredAs'), 'legal_form': (e.get('legalForm') or {}).get('id'),
                'legal_address': _addr(e.get('legalAddress')), 'hq_address': _addr(e.get('headquartersAddress')),
                'registration_status': a['registration'].get('status'),
                'registered': (a['registration'].get('initialRegistrationDate') or '')[:10],
                'next_renewal': (a['registration'].get('nextRenewalDate') or '')[:10],
                'url': f'https://search.gleif.org/#/record/{a["lei"]}',
            })
        return out
    return R.GLEIF.fetch(('lei', q.lower(), size), run)


def opencorporates(query, jurisdiction=None):
    if not R.OPENCORPORATES.configured:
        raise ProviderUnavailable(f'Set {R.OPENCORPORATES.key_env}')

    def run():
        params = {'q': query, 'api_token': R.OPENCORPORATES.api_key, 'per_page': 20}
        if jurisdiction:
            params['jurisdiction_code'] = jurisdiction
        resp = requests.get('https://api.opencorporates.com/v0.4/companies/search', params=params,
                            headers=UA, timeout=20)
        if resp.status_code == 401:
            raise ValueError('Token OpenCorporates tidak valid')
        resp.raise_for_status()
        out = []
        for item in resp.json()['results']['companies']:
            c = item['company']
            out.append({'name': c.get('name'), 'number': c.get('company_number'),
                        'jurisdiction': c.get('jurisdiction_code'), 'status': c.get('current_status'),
                        'incorporated': c.get('incorporation_date'), 'type': c.get('company_type'),
                        'address': c.get('registered_address_in_full'), 'url': c.get('opencorporates_url')})
        return out
    return R.OPENCORPORATES.fetch((query.lower(), jurisdiction), run)


def orcid(query, rows=10):
    def run():
        resp = requests.get('https://pub.orcid.org/v3.0/expanded-search/', headers=UA, timeout=20,
                            params={'q': query, 'rows': rows})
        resp.raise_for_status()
        return [{'orcid': r['orcid-id'], 'name': ' '.join(filter(None, [r.get('given-names'), r.get('family-names')])),
                 'institutions': r.get('institution-name', [])[:4],
                 'url': f'https://orcid.org/{r["orcid-id"]}'}
                for r in resp.json().get('expanded-result') or []]
    return R.ORCID.fetch((query.lower(), rows), run)


def openalex_authors(query, per_page=10):
    def run():
        resp = requests.get('https://api.openalex.org/authors', headers=UA, timeout=20,
                            params={'search': query, 'per_page': per_page, 'mailto': ''})
        resp.raise_for_status()
        out = []
        for a in resp.json().get('results', []):
            inst = a.get('last_known_institutions') or []
            out.append({'name': a.get('display_name'), 'id': a.get('id'), 'orcid': a.get('orcid'),
                        'works': a.get('works_count'), 'citations': a.get('cited_by_count'),
                        'h_index': (a.get('summary_stats') or {}).get('h_index'),
                        'institution': inst[0].get('display_name') if inst else None,
                        'country': inst[0].get('country_code') if inst else None,
                        'topics': [t.get('display_name') for t in (a.get('topics') or [])[:4]],
                        'url': a.get('id')})
        return out
    return R.OPENALEX.fetch((query.lower(), per_page), run)


def registry_links(query):
    q = quote(query)
    return [
        ('AHU Online (Kemenkum) — profil PT', 'https://ahu.go.id/pencarian/profil-pt', 'Cari manual (captcha).'),
        ('OSS RBA — NIB perusahaan', 'https://oss.go.id/informasi/pencarian-perusahaan', 'Butuh pencarian manual.'),
        ('IDX — emiten', f'https://www.idx.co.id/id/perusahaan-tercatat/profil-perusahaan-tercatat?search={q}', None),
        ('LPSE / SPSE — penyedia pengadaan', f'https://www.google.com/search?q={quote(chr(34) + query + chr(34) + " site:lpse.*.go.id")}', None),
        ('Direktori Putusan MA', f'https://putusan3.mahkamahagung.go.id/search.html?q={q}', 'Putusan pengadilan.'),
        ('PSE Kominfo/Komdigi', 'https://pse.komdigi.go.id/', 'Penyelenggara Sistem Elektronik.'),
        ('OpenCorporates (web)', f'https://opencorporates.com/companies?q={q}', None),
        ('Google Scholar', f'https://scholar.google.com/scholar?q={q}', None),
        ('SINTA (peneliti Indonesia)', f'https://sinta.kemdiktisaintek.go.id/authors?q={q}', None),
        ('LinkedIn (via Google)', f'https://www.google.com/search?q={quote(chr(34) + query + chr(34) + " site:linkedin.com")}', None),
    ]


def search(query, kinds=('company', 'person')):
    query = (query or '').strip()
    if len(query) < 3:
        raise ValueError('Minimal 3 karakter')
    tasks = {}
    if 'company' in kinds:
        tasks['gleif'] = lambda: gleif(query)
        tasks['opencorporates'] = lambda: opencorporates(query)
    if 'person' in kinds:
        tasks['orcid'] = lambda: orcid(query)
        tasks['openalex'] = lambda: openalex_authors(query)
    results = {}
    with ThreadPoolExecutor(max_workers=len(tasks) or 1) as pool:
        futures = {k: pool.submit(f) for k, f in tasks.items()}
    for key, fut in futures.items():
        try:
            results[key] = {'status': 'ok', 'items': fut.result()}
        except ProviderUnavailable as e:
            results[key] = {'status': 'no_key', 'items': [], 'message': str(e)}
        except Exception as e:
            results[key] = {'status': 'error', 'items': [], 'message': str(e)[:200]}
    return {
        'query': query,
        'results': results,
        'links': [{'label': lbl, 'url': url, 'note': note} for lbl, url, note in registry_links(query)],
    }
