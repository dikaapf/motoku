import dns.resolver


RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SPF', 'CAA', 'SRV']


def resolve(domain, record_type='A'):
    domain = domain.strip().lower()
    results = []
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=5)
        for r in answers:
            results.append(str(r))
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        raise ValueError(f'Domain {domain} tidak ditemukan')
    except Exception as e:
        raise ValueError(f'Gagal resolve {record_type}: {e}')
    return results


def resolve_all(domain):
    domain = domain.strip().lower()
    all_results = {}
    for rtype in RECORD_TYPES:
        try:
            answers = resolve(domain, rtype)
            if answers:
                all_results[rtype] = answers
        except Exception:
            all_results[rtype] = []
    return all_results
