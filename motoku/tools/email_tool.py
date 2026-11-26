"""Email intelligence: syntax, MX, SMTP mailbox probe, disposable/free/role
detection, Gravatar, HIBP breaches and EmailRep reputation."""

import hashlib
import os
import re
import smtplib
import socket

import requests

from services import resolver
from services.providers import ProviderUnavailable, QuotaExceeded
from services.providers.registry import EMAILREP, GRAVATAR, HIBP

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
DISPOSABLE_PATH = os.path.join(DATA_DIR, 'disposable_domains.txt')
DISPOSABLE_URL = (
    'https://raw.githubusercontent.com/disposable-email-domains/'
    'disposable-email-domains/main/disposable_email_blocklist.conf'
)

EMAIL_RE = re.compile(r'^[A-Za-z0-9.!#$%&\'*+/=?^_`{|}~\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,63}$')
EMAILREP_URL = 'https://emailrep.io/{email}'
HIBP_URL = 'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'
USER_AGENT = 'Motoku-OSINT/1.1'

# Fallback when the bundled blocklist file is missing.
_BUILTIN_DISPOSABLE = {
    'mailinator.com', '10minutemail.com', 'guerrillamail.com', 'tempmail.com',
    'temp-mail.org', 'yopmail.com', 'trashmail.com', 'getnada.com',
    'sharklasers.com', 'dispostable.com', 'maildrop.cc', 'throwawaymail.com',
}
FREE_PROVIDERS = {
    'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.id', 'ymail.com',
    'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'icloud.com',
    'me.com', 'aol.com', 'proton.me', 'protonmail.com', 'gmx.com', 'gmx.net',
    'mail.com', 'zoho.com', 'yandex.com', 'yandex.ru', 'tutanota.com',
    'mail.ru', 'qq.com', '163.com', 'rocketmail.com',
}
ROLE_ACCOUNTS = {
    'admin', 'administrator', 'info', 'support', 'sales', 'contact', 'help',
    'billing', 'abuse', 'postmaster', 'hostmaster', 'webmaster', 'noreply',
    'no-reply', 'security', 'marketing', 'hr', 'jobs', 'office', 'team',
    'hello', 'root', 'mail', 'cs', 'finance',
}

_disposable_cache = None


def disposable_domains():
    global _disposable_cache
    if _disposable_cache is None:
        domains = set(_BUILTIN_DISPOSABLE)
        if os.path.exists(DISPOSABLE_PATH):
            with open(DISPOSABLE_PATH, encoding='utf-8') as fh:
                domains |= {
                    line.strip().lower() for line in fh
                    if line.strip() and not line.startswith('#')
                }
        _disposable_cache = domains
    return _disposable_cache


def update_disposable_list(timeout=30):
    global _disposable_cache
    resp = requests.get(DISPOSABLE_URL, timeout=timeout)
    resp.raise_for_status()
    lines = [x for x in resp.text.splitlines() if x.strip()]
    if len(lines) < 100:
        raise ValueError('Daftar disposable domain tidak valid')
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(DISPOSABLE_PATH, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(lines) + '\n')
    _disposable_cache = None
    return len(lines)


def is_disposable(domain):
    domain = domain.lower()
    known = disposable_domains()
    parts = domain.split('.')
    return any('.'.join(parts[i:]) in known for i in range(len(parts) - 1))


def parse(email):
    email = (email or '').strip()
    if not EMAIL_RE.match(email) or '..' in email:
        raise ValueError('Format email tidak valid')
    local, domain = email.rsplit('@', 1)
    return local, domain.lower()


def mx_records(domain):
    records = []
    for raw in resolver.resolve(domain, 'MX'):
        prio, _, host = raw.partition(' ')
        try:
            records.append({'priority': int(prio), 'host': host.strip().rstrip('.')})
        except ValueError:
            continue
    if records:
        records.sort(key=lambda r: r['priority'])
        return [r for r in records if r['host']]  # null MX (".") means no mail
    # RFC 5321 implicit MX: fall back to the A record.
    if resolver.resolve(domain, 'A'):
        return [{'priority': 0, 'host': domain, 'implicit': True}]
    return []


def smtp_probe(email, mx_host, timeout=8):
    """Ask the MX whether it accepts the mailbox, without sending mail.

    Also probes a random address to detect catch-all servers. Many networks
    block outbound port 25, in which case the result is ``unknown``.
    """
    result = {'host': mx_host, 'deliverable': None, 'catch_all': None, 'detail': ''}
    domain = email.rsplit('@', 1)[1]
    random_rcpt = f'motoku-{hashlib.md5(email.encode()).hexdigest()[:12]}@{domain}'
    try:
        with smtplib.SMTP(mx_host, 25, timeout=timeout) as smtp:
            smtp.ehlo_or_helo_if_needed()
            if smtp.has_extn('starttls'):
                try:
                    smtp.starttls()
                    smtp.ehlo()
                except smtplib.SMTPException:
                    pass
            smtp.mail('probe@example.com')
            code, msg = smtp.rcpt(email)
            result['code'] = code
            result['detail'] = msg.decode(errors='replace')[:200]
            result['deliverable'] = code in (250, 251)
            rcode, _ = smtp.rcpt(random_rcpt)
            result['catch_all'] = rcode in (250, 251)
    except (OSError, smtplib.SMTPException, socket.timeout) as e:
        result['detail'] = f'Tidak dapat terhubung ke port 25: {type(e).__name__}'
    return result


def gravatar(email):
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()

    def run():
        resp = requests.get(f'https://en.gravatar.com/{h}.json',
                            headers={'User-Agent': USER_AGENT}, timeout=6)
        if resp.status_code != 200:
            return {'found': False}
        entry = (resp.json().get('entry') or [{}])[0]
        return {
            'found': True,
            'profile_url': entry.get('profileUrl') or f'https://gravatar.com/{h}',
            'display_name': entry.get('displayName', ''),
            'avatar': f'https://www.gravatar.com/avatar/{h}?s=200',
            'about': entry.get('aboutMe', ''),
            'location': entry.get('currentLocation', ''),
            'accounts': [
                {'name': a.get('shortname') or a.get('domain'), 'url': a.get('url')}
                for a in entry.get('accounts', []) if a.get('url')
            ],
        }

    try:
        data = GRAVATAR.fetch(h, run)
    except Exception:
        return None
    return data if data.get('found') else None


def hibp(email):
    """Return ``{'status': ..., 'breaches': [...]}`` from Have I Been Pwned."""
    if not HIBP.configured:
        return {'status': 'no_key', 'breaches': [],
                'message': f'Set {HIBP.key_env} untuk mengaktifkan HIBP'}

    def run():
        resp = requests.get(
            HIBP_URL.format(email=requests.utils.quote(email)),
            params={'truncateResponse': 'false'},
            headers={'hibp-api-key': HIBP.api_key, 'User-Agent': USER_AGENT},
            timeout=10,
        )
        if resp.status_code == 404:
            return {'status': 'clean', 'breaches': []}
        if resp.status_code == 429:
            raise ValueError('HIBP rate limit, coba lagi sebentar')
        if resp.status_code == 401:
            raise ValueError('HIBP API key tidak valid')
        resp.raise_for_status()
        breaches = [
            {
                'name': b.get('Name'),
                'title': b.get('Title'),
                'domain': b.get('Domain'),
                'date': b.get('BreachDate'),
                'pwn_count': b.get('PwnCount'),
                'data_classes': b.get('DataClasses', []),
                'verified': b.get('IsVerified'),
            }
            for b in resp.json()
        ]
        breaches.sort(key=lambda b: b['date'] or '', reverse=True)
        return {'status': 'breached', 'breaches': breaches}

    try:
        return HIBP.fetch(email.lower(), run)
    except (ProviderUnavailable, QuotaExceeded, ValueError, requests.RequestException) as e:
        return {'status': 'error', 'breaches': [], 'message': str(e)}


def emailrep(email):
    def run():
        resp = requests.get(EMAILREP_URL.format(email=email),
                            headers={'User-Agent': USER_AGENT}, timeout=10)
        if resp.status_code == 429:
            raise ValueError('Rate limited oleh emailrep.io (10 req/jam tanpa key)')
        if resp.status_code != 200:
            raise ValueError(f'emailrep.io mengembalikan {resp.status_code}')
        return resp.json()

    return EMAILREP.fetch(email.lower(), run)


def _risk_score(report):
    score = 0
    notes = []
    if report['disposable']:
        score += 50
        notes.append('Domain email sekali pakai (disposable)')
    if not report['mx']:
        score += 30
        notes.append('Domain tidak memiliki MX — tidak bisa menerima email')
    smtp = report.get('smtp') or {}
    if smtp.get('deliverable') is False:
        score += 30
        notes.append('Server menolak mailbox ini')
    if smtp.get('catch_all'):
        notes.append('Server catch-all: semua alamat diterima, validasi kurang pasti')
    if report['role']:
        score += 5
        notes.append('Alamat role/generik, bukan individu')
    breaches = (report.get('hibp') or {}).get('breaches') or []
    if breaches:
        score += min(30, 5 * len(breaches))
        notes.append(f'Muncul di {len(breaches)} data breach')
    level = 'tinggi' if score >= 50 else 'sedang' if score >= 20 else 'rendah'
    return min(score, 100), level, notes


def investigate(email, smtp_check=False, use_emailrep=True):
    local, domain = parse(email)
    email = f'{local}@{domain}'
    report = {
        'email': email,
        'local': local,
        'domain': domain,
        'valid_syntax': True,
        'disposable': is_disposable(domain),
        'free_provider': domain in FREE_PROVIDERS,
        'role': local.lower().split('+')[0] in ROLE_ACCOUNTS,
        'plus_alias': '+' in local,
        'mx': mx_records(domain),
        'smtp': None,
        'gravatar': gravatar(email),
        'hibp': hibp(email),
        'emailrep': None,
        'emailrep_error': None,
    }
    if smtp_check and report['mx']:
        report['smtp'] = smtp_probe(email, report['mx'][0]['host'])
    if use_emailrep:
        try:
            report['emailrep'] = emailrep(email)
        except Exception as e:
            report['emailrep_error'] = str(e)
    report['risk_score'], report['risk_level'], report['risk_notes'] = _risk_score(report)
    return report
