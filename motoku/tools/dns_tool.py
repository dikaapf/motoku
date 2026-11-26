from services import resolver

RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA', 'SRV']

# Common DKIM selectors. There is no way to enumerate selectors via DNS,
# so we probe the most frequently used ones.
DKIM_SELECTORS = [
    'default', 'google', 'selector1', 'selector2', 'k1', 'mail',
    's1', 's2', 'dkim', 'mandrill', 'sendgrid', 'mailchimp',
]


def resolve(domain, record_type='A'):
    domain = domain.strip().lower()
    try:
        return resolver.resolve(domain, record_type, raise_nx=True)
    except resolver.NXDomain:
        raise ValueError(f'Domain {domain} tidak ditemukan')


def _resolve_optional(name, record_type):
    """Resolve an auxiliary record without failing the whole lookup."""
    return resolver.resolve(name, record_type)


def _spf_from_txt(txt_records):
    return [r for r in txt_records if 'v=spf1' in r.lower()]


def _dnssec_records(domain):
    records = []
    for rtype in ('DS', 'DNSKEY'):
        for r in _resolve_optional(domain, rtype):
            records.append(f'{rtype}: {r}')
    return records


def resolve_all(domain):
    domain = domain.strip().lower()
    results = {}

    for rtype in RECORD_TYPES:
        results[rtype] = resolve(domain, rtype)

    # SPF lives inside TXT records; "SPF" is not a DNS record type.
    results['SPF'] = _spf_from_txt(results.get('TXT', []))

    # DMARC policy is published as a TXT record on _dmarc.<domain>.
    results['DMARC'] = _resolve_optional(f'_dmarc.{domain}', 'TXT')

    # DKIM public keys live on <selector>._domainkey.<domain>.
    dkim = []
    for selector in DKIM_SELECTORS:
        for r in _resolve_optional(f'{selector}._domainkey.{domain}', 'TXT'):
            dkim.append(f'{selector}: {r}')
    results['DKIM'] = dkim

    results['DNSSEC'] = _dnssec_records(domain)
    return results
