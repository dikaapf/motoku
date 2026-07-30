import phonenumbers
from phonenumbers import carrier, geocoder, timezone


def track(number):
    default_region = "ID"
    parsed = phonenumbers.parse(number, default_region)
    region_code = phonenumbers.region_code_for_number(parsed)
    provider = carrier.name_for_number(parsed, "en")
    location = geocoder.description_for_number(parsed, "id")
    is_valid = phonenumbers.is_valid_number(parsed)
    is_possible = phonenumbers.is_possible_number(parsed)
    intl_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    e164_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    ntype = phonenumbers.number_type(parsed)
    tz = timezone.time_zones_for_number(parsed)
    tz_str = ', '.join(tz)

    type_label = {
        phonenumbers.PhoneNumberType.MOBILE: 'Mobile',
        phonenumbers.PhoneNumberType.FIXED_LINE: 'Fixed Line',
        phonenumbers.PhoneNumberType.VOIP: 'VoIP',
    }.get(ntype, 'Lainnya')

    return {
        'location': location or 'Tidak diketahui',
        'region_code': region_code,
        'timezone': tz_str,
        'operator': provider or 'Tidak diketahui',
        'valid': 'Ya' if is_valid else 'Tidak',
        'possible': 'Ya' if is_possible else 'Tidak',
        'international': intl_format,
        'e164': e164_format,
        'national': str(parsed.national_number),
        'country_code': f'+{parsed.country_code}',
        'type': type_label,
    }
