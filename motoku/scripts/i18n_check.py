#!/usr/bin/env python3
"""List translatable strings missing from translations/en.json.

    python scripts/i18n_check.py            # report
    python scripts/i18n_check.py --write    # add missing keys (value = source) for translators
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from services.i18n import extract_strings  # noqa: E402

path = os.path.join(ROOT, 'translations', 'en.json')
catalog = json.load(open(path, encoding='utf-8')) if os.path.exists(path) else {}
strings = extract_strings(ROOT)
missing = sorted(s for s in strings if s not in catalog)
unused = sorted(k for k in catalog if k not in strings)
print(f'{len(strings)} string, {len(missing)} belum diterjemahkan, {len(unused)} tidak terpakai')
for s in missing:
    print('  MISSING:', s)
if '--write' in sys.argv and missing:
    catalog.update({s: s for s in missing})
    json.dump(dict(sorted(catalog.items())), open(path, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('ditulis ke', path)
sys.exit(1 if missing else 0)
