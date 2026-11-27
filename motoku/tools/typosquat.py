"""Typosquatting & homograph detection (dnstwist-style permutation engine).

Generates look-alike domains (omission, repetition, transposition, keyboard
replacement, insertion, bitsquatting, homoglyphs, hyphenation, vowel swap,
addition, dictionary, TLD swap, subdomain), resolves them concurrently and
reports which are registered, with A/MX/NS records. Also analyses a single
domain for IDN homograph tricks (mixed scripts, confusable characters).
"""

import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed

from services import resolver

KEYBOARD = {
    'q': '12wa', 'w': '23qeas', 'e': '34wrsd', 'r': '45etdf', 't': '56ryfg', 'y': '67tugh',
    'u': '78yihj', 'i': '89uojk', 'o': '90ipkl', 'p': '0ol', 'a': 'qwsz', 's': 'weadzx',
    'd': 'erfscx', 'f': 'rtgdvc', 'g': 'tyhfbv', 'h': 'yujgnb', 'j': 'uikhmn', 'k': 'iolmj',
    'l': 'opk', 'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm',
    'm': 'njk', '1': '2q', '2': '13wq', '3': '24ew', '4': '35re', '5': '46tr', '6': '57yt',
    '7': '68uy', '8': '79iu', '9': '80oi', '0': '9po',
}
# ASCII-visible look-alikes plus common Unicode confusables (Cyrillic/Greek/Latin ext.)
HOMOGLYPHS = {
    'a': ['à', 'á', 'â', 'ã', 'ä', 'å', 'ɑ', 'а', 'ạ'], 'b': ['d', 'lb', 'ʙ', 'Ь', 'ḃ'],
    'c': ['e', 'ƈ', 'ċ', 'ć', 'с'], 'd': ['b', 'cl', 'dl', 'ɗ', 'đ', 'ԁ'],
    'e': ['c', 'é', 'ê', 'ë', 'ē', 'ė', 'е', 'ẹ'], 'g': ['q', 'ɢ', 'ɡ', 'ġ', 'ğ'],
    'h': ['lh', 'ĥ', 'ȟ', 'һ'], 'i': ['1', 'l', 'í', 'ï', 'ı', 'і', 'ị'],
    'j': ['ʝ', 'ј'], 'k': ['lk', 'ik', 'lc', 'ḳ', 'κ'], 'l': ['1', 'i', 'ɫ', 'ł', 'ӏ'],
    'm': ['n', 'nn', 'rn', 'rr', 'ṁ', 'м'], 'n': ['m', 'r', 'ń', 'ñ', 'п'],
    'o': ['0', 'ο', 'о', 'ö', 'ó', 'ọ', 'ø'], 'p': ['ρ', 'р', 'ṗ'], 'q': ['g', 'ԛ'],
    'r': ['ʀ', 'г', 'ŕ'], 's': ['ʂ', 'ś', 'ṡ', 'ѕ'], 't': ['τ', 'ţ', 'ť'],
    'u': ['µ', 'ü', 'ú', 'ù', 'υ'], 'v': ['ѵ', 'ν', 'ṿ'], 'w': ['vv', 'ŵ', 'ẁ', 'ẃ', 'ԝ'],
    'x': ['х', 'ẋ'], 'y': ['ʏ', 'ý', 'ÿ', 'у'], 'z': ['ʐ', 'ż', 'ź'],
}
VOWELS = 'aeiou'
DICTIONARY = ['login', 'secure', 'account', 'support', 'verify', 'update', 'mail', 'app',
              'online', 'id', 'portal', 'my', 'web', 'auth', 'pay', 'help', 'bank', 'official']
ALT_TLDS = ['com', 'net', 'org', 'co', 'io', 'id', 'co.id', 'info', 'biz', 'xyz', 'online',
            'site', 'app', 'me', 'cc', 'top', 'shop', 'store', 'web.id', 'my.id', 'or.id']
SUFFIX_2LD = ('co.id', 'ac.id', 'go.id', 'or.id', 'web.id', 'my.id', 'sch.id', 'co.uk', 'org.uk',
              'com.au', 'co.jp', 'com.sg', 'com.my', 'co.in', 'com.br')


def split_domain(domain):
    domain = domain.strip().lower().rstrip('.')
    domain = domain.split('://')[-1].split('/')[0]
    if domain.startswith('www.'):
        domain = domain[4:]
    try:
        domain = domain.encode('ascii').decode('idna') if domain.startswith('xn--') or '.xn--' in domain \
            else domain
    except UnicodeError:
        pass
    for suffix in SUFFIX_2LD:
        if domain.endswith('.' + suffix):
            name = domain[: -len(suffix) - 1].split('.')[-1]
            return name, suffix
    parts = domain.split('.')
    if len(parts) < 2:
        raise ValueError('Domain tidak valid')
    return parts[-2], parts[-1]


def _valid_label(label):
    """Validate a (possibly Unicode) DNS label via its IDNA/punycode form."""
    if label.isascii():
        ascii_label = label
        if '--' in label[2:4]:
            return False  # reserved for A-labels such as xn--
    else:
        try:
            ascii_label = label.encode('idna').decode()
        except UnicodeError:
            return False
    return 0 < len(ascii_label) <= 63 and not ascii_label.startswith('-') and not ascii_label.endswith('-')


def permutations(domain, include_homoglyphs=True, include_tld=True, include_dictionary=True):
    """Return ``{fqdn: fuzzer}`` excluding the original domain."""
    name, tld = split_domain(domain)
    out = {}

    def add(label, fuzzer, suffix=tld):
        label = label.strip('-')
        if label and label != name and _valid_label(label):
            fqdn = f'{label}.{suffix}'
            out.setdefault(fqdn, fuzzer)

    n = len(name)
    for i in range(n):
        add(name[:i] + name[i + 1:], 'omission')
        add(name[:i] + name[i] * 2 + name[i + 1:], 'repetition')
        if i < n - 1:
            add(name[:i] + name[i + 1] + name[i] + name[i + 2:], 'transposition')
        for k in KEYBOARD.get(name[i], ''):
            add(name[:i] + k + name[i + 1:], 'replacement')
            add(name[:i] + k + name[i:], 'insertion')
        if name[i] in VOWELS:
            for v in VOWELS:
                if v != name[i]:
                    add(name[:i] + v + name[i + 1:], 'vowel-swap')
        for bit in range(8):
            flipped = chr(ord(name[i]) ^ (1 << bit))
            if flipped.isalnum() and flipped.isascii() and flipped.islower() or flipped.isdigit():
                add(name[:i] + flipped + name[i + 1:], 'bitsquatting')
        if 0 < i < n:
            add(name[:i] + '-' + name[i:], 'hyphenation')
            add(name[:i] + '.' + name[i:], 'subdomain')
        if include_homoglyphs:
            for g in HOMOGLYPHS.get(name[i], []):
                add(name[:i] + g + name[i + 1:], 'homoglyph')
    for c in 'abcdefghijklmnopqrstuvwxyz0123456789':
        add(name + c, 'addition')
    if include_dictionary:
        for word in DICTIONARY:
            add(f'{name}-{word}', 'dictionary')
            add(f'{word}-{name}', 'dictionary')
            add(f'{name}{word}', 'dictionary')
    if include_tld:
        for alt in ALT_TLDS:
            if alt != tld:
                out.setdefault(f'{name}.{alt}', 'tld-swap')
    out.pop(f'{name}.{tld}', None)
    return out


def to_ascii(fqdn):
    try:
        return fqdn.encode('idna').decode()
    except UnicodeError:
        return None


def _check(fqdn):
    ascii_name = to_ascii(fqdn)
    if not ascii_name:
        return None
    a = resolver.resolve(ascii_name, 'A')
    ns = [] if a else resolver.resolve(ascii_name, 'NS')
    if not a and not ns:
        return None
    return {'domain': fqdn, 'ascii': ascii_name, 'a': a[:4], 'ns': ns[:3],
            'mx': resolver.resolve(ascii_name, 'MX')[:3]}


def scan(domain, max_candidates=1500, workers=48, progress=None, **kwargs):
    name, tld = split_domain(domain)
    original = f'{name}.{tld}'
    perms = permutations(original, **kwargs)
    items = list(perms.items())[:max_candidates]
    original_ips = set(resolver.resolve(original, 'A'))
    registered = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_check, fqdn): (fqdn, fuzzer) for fqdn, fuzzer in items}
        for i, fut in enumerate(as_completed(futures), 1):
            fqdn, fuzzer = futures[fut]
            try:
                hit = fut.result()
            except Exception:
                hit = None
            if hit:
                hit['fuzzer'] = fuzzer
                hit['same_ip'] = bool(original_ips & set(hit['a']))
                hit['risk'] = _risk(hit, short_name=len(name) <= SHORT_NAME)
                registered.append(hit)
            if progress and i % 50 == 0:
                progress(100 * i / len(items), f'{i}/{len(items)} dicek, {len(registered)} terdaftar')
    order = {'high': 0, 'medium': 1, 'low': 2}
    registered.sort(key=lambda r: (order[r['risk']], r['fuzzer'], r['domain']))
    by_fuzzer = {}
    for fuzzer in perms.values():
        by_fuzzer[fuzzer] = by_fuzzer.get(fuzzer, 0) + 1
    return {
        'domain': original,
        'generated': len(perms),
        'checked': len(items),
        'registered_count': len(registered),
        'registered': registered,
        'short_name': len(name) <= SHORT_NAME,
        'fuzzers': by_fuzzer,
        'homograph': analyse_homograph(domain),
    }


# For very short brand names most one-character variants are unrelated,
# legitimately registered domains; only homoglyphs stay suspicious.
SHORT_NAME = 5


def _risk(hit, short_name=False):
    if short_name and hit['fuzzer'] != 'homoglyph':
        return 'low'
    if hit['same_ip']:
        return 'low'  # likely owned by the brand (defensive registration / redirect)
    if hit['mx'] and hit['fuzzer'] in ('homoglyph', 'omission', 'transposition', 'replacement',
                                        'bitsquatting', 'repetition', 'insertion', 'vowel-swap'):
        return 'high'  # can send/receive mail on a near-identical name
    if hit['fuzzer'] in ('homoglyph', 'dictionary') or hit['mx']:
        return 'medium'
    return 'low'


# ── Homograph analysis ──
def _script(ch):
    if ch.isascii():
        return 'Latin' if ch.isalpha() else 'Common'
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return 'Unknown'
    for script in ('LATIN', 'CYRILLIC', 'GREEK', 'ARMENIAN', 'HEBREW', 'ARABIC', 'CJK', 'HANGUL',
                   'HIRAGANA', 'KATAKANA', 'THAI', 'DEVANAGARI', 'GEORGIAN', 'CHEROKEE'):
        if name.startswith(script):
            return script.title()
    return 'Other'


_CONFUSABLE = {g: base for base, glyphs in HOMOGLYPHS.items() for g in glyphs if len(g) == 1 and not g.isascii()}


def analyse_homograph(domain):
    raw = (domain or '').strip().lower().split('://')[-1].split('/')[0]
    try:
        unicode_name = raw.encode('ascii').decode('idna') if 'xn--' in raw else raw
    except UnicodeError:
        unicode_name = raw
    ascii_name = to_ascii(unicode_name) or raw
    findings = []
    for label in unicode_name.split('.'):
        scripts = {_script(c) for c in label if c.isalpha()}
        scripts.discard('Common')
        if len(scripts) > 1:
            findings.append(f'Label "{label}" mencampur skrip: {", ".join(sorted(scripts))}')
        confusables = [(c, _CONFUSABLE[c]) for c in label if c in _CONFUSABLE]
        if confusables:
            findings.append('Karakter mirip Latin: ' + ', '.join(
                f'{c} (U+{ord(c):04X}, mirip "{b}")' for c, b in confusables))
    skeleton = ''.join(_CONFUSABLE.get(c, c) for c in unicode_name)
    skeleton = unicodedata.normalize('NFKD', skeleton).encode('ascii', 'ignore').decode()
    return {
        'input': raw,
        'unicode': unicode_name,
        'punycode': ascii_name,
        'is_idn': unicode_name != ascii_name,
        'skeleton': skeleton,
        'suspicious': bool(findings),
        'findings': findings,
    }
