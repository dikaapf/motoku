"""Phone number intelligence: parsing, Indonesian operator prefixes and
footprinting links.

Messenger presence (WhatsApp/Telegram) is *not* probed automatically: doing so
needs unofficial automation that breaks those services' terms and is a common
stalking technique. Instead the analyst gets direct links to check manually.
"""

from urllib.parse import quote

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

# Indonesian mobile prefixes (original allocation; mobile number portability
# can move numbers between operators, so treat this as the *issuing* operator).
ID_PREFIXES = {
    'Telkomsel': ['0811', '0812', '0813', '0821', '0822', '0823', '0851', '0852', '0853'],
    'Indosat Ooredoo': ['0814', '0815', '0816', '0855', '0856', '0857', '0858'],
    'XL Axiata': ['0817', '0818', '0819', '0859', '0877', '0878'],
    'AXIS (XL)': ['0831', '0832', '0833', '0838'],
    'Tri (Indosat)': ['0895', '0896', '0897', '0898', '0899'],
    'Smartfren': ['0881', '0882', '0883', '0884', '0885', '0886', '0887', '0888', '0889'],
    'by.U (Telkomsel)': ['0851'],
}
ID_PREFIX_LOOKUP = {}
for _op, _prefixes in ID_PREFIXES.items():
    for _p in _prefixes:
        ID_PREFIX_LOOKUP.setdefault(_p, _op)

TYPE_LABELS = {
    phonenumbers.PhoneNumberType.MOBILE: 'Mobile',
    phonenumbers.PhoneNumberType.FIXED_LINE: 'Fixed Line',
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: 'Fixed Line / Mobile',
    phonenumbers.PhoneNumberType.VOIP: 'VoIP',
    phonenumbers.PhoneNumberType.TOLL_FREE: 'Toll Free',
    phonenumbers.PhoneNumberType.PREMIUM_RATE: 'Premium Rate',
    phonenumbers.PhoneNumberType.SHARED_COST: 'Shared Cost',
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: 'Personal',
    phonenumbers.PhoneNumberType.PAGER: 'Pager',
    phonenumbers.PhoneNumberType.UAN: 'UAN',
    phonenumbers.PhoneNumberType.VOICEMAIL: 'Voicemail',
}


def indonesian_operator(parsed):
    if parsed.country_code != 62:
        return None
    national = '0' + str(parsed.national_number)
    return ID_PREFIX_LOOKUP.get(national[:4])


def number_formats(parsed):
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    intl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
    digits = e164.lstrip('+')
    local = '0' + str(parsed.national_number) if parsed.country_code == 62 else str(parsed.national_number)
    variants = [e164, digits, intl, national, local, intl.replace(' ', '-'), f'+{parsed.country_code} {parsed.national_number}']
    return list(dict.fromkeys(v for v in variants if v))


def footprint_links(parsed):
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    digits = e164.lstrip('+')
    formats = number_formats(parsed)
    or_query = ' OR '.join(f'"{f}"' for f in formats[:5])
    searches = [
        ('Google — semua format', f'https://www.google.com/search?q={quote(or_query)}'),
        ('Bing — semua format', f'https://www.bing.com/search?q={quote(or_query)}'),
        ('DuckDuckGo', f'https://duckduckgo.com/?q={quote(or_query)}'),
        ('Google — situs sosial', 'https://www.google.com/search?q=' + quote(
            f'({or_query}) (site:facebook.com OR site:instagram.com OR site:linkedin.com OR site:twitter.com OR site:x.com OR site:tiktok.com)')),
        ('Google — marketplace & iklan', 'https://www.google.com/search?q=' + quote(
            f'({or_query}) (site:tokopedia.com OR site:bukalapak.com OR site:olx.co.id OR site:shopee.co.id OR site:kaskus.co.id)')),
        ('Google — dokumen', 'https://www.google.com/search?q=' + quote(f'({or_query}) (filetype:pdf OR filetype:xlsx OR filetype:docx)')),
        ('Google — paste/leak', 'https://www.google.com/search?q=' + quote(f'({or_query}) (site:pastebin.com OR site:ghostbin.co OR site:justpaste.it)')),
    ]
    messengers = [
        ('WhatsApp (wa.me)', f'https://wa.me/{digits}', 'Buka untuk melihat apakah nomor terdaftar dan foto/nama bisnis (jika publik).'),
        ('Telegram', f'https://t.me/+{digits}', 'Hanya terbuka jika pemilik mengizinkan ditemukan lewat nomor.'),
        ('Viber', f'viber://chat?number=%2B{digits}', 'Membuka aplikasi Viber jika terpasang.'),
        ('Truecaller', f'https://www.truecaller.com/search/{phonenumbers.region_code_for_number(parsed).lower()}/{parsed.national_number}', 'Butuh login.'),
        ('Sync.me', f'https://sync.me/search/?number={digits}', 'Butuh login.'),
    ]
    return {
        'searches': [{'label': lbl, 'url': url} for lbl, url in searches],
        'messengers': [{'label': lbl, 'url': url, 'note': note} for lbl, url, note in messengers],
    }


def track(number, default_region='ID'):
    try:
        parsed = phonenumbers.parse(number, default_region)
    except phonenumbers.NumberParseException as e:
        raise ValueError(f'Nomor tidak dapat diparse: {e}')
    region_code = phonenumbers.region_code_for_number(parsed)
    provider = carrier.name_for_number(parsed, 'en')
    id_operator = indonesian_operator(parsed)
    is_valid = phonenumbers.is_valid_number(parsed)
    ntype = phonenumbers.number_type(parsed)
    return {
        'input': number,
        'location': geocoder.description_for_number(parsed, 'id') or 'Tidak diketahui',
        'region_code': region_code,
        'timezone': ', '.join(timezone.time_zones_for_number(parsed)),
        'operator': provider or id_operator or 'Tidak diketahui',
        'operator_prefix': id_operator,
        'prefix': ('0' + str(parsed.national_number))[:4] if parsed.country_code == 62 else None,
        'valid': 'Ya' if is_valid else 'Tidak',
        'possible': 'Ya' if phonenumbers.is_possible_number(parsed) else 'Tidak',
        'is_valid': is_valid,
        'international': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        'e164': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        'national': str(parsed.national_number),
        'country_code': f'+{parsed.country_code}',
        'type': TYPE_LABELS.get(ntype, 'Lainnya'),
        'formats': number_formats(parsed),
        'footprint': footprint_links(parsed),
    }
