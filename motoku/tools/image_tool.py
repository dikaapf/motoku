"""Image forensics: metadata/EXIF + GPS, hashes, OCR and reverse-image links.

Uploaded images are processed in memory and never written to disk.
"""

import hashlib
import io
import json
import os
import shutil
import subprocess
from urllib.parse import quote

import requests

MAX_BYTES = 15 * 1024 * 1024
UA = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Motoku-OSINT/1.4'}
# EXIF tags that are interesting for an investigator.
KEY_TAGS = ['Make', 'Model', 'LensModel', 'Software', 'DateTime', 'DateTimeOriginal',
            'DateTimeDigitized', 'OffsetTimeOriginal', 'Artist', 'Copyright', 'HostComputer',
            'BodySerialNumber', 'LensSerialNumber', 'CameraOwnerName', 'ImageDescription',
            'XPAuthor', 'XPComment', 'UserComment', 'ExposureTime', 'FNumber', 'ISOSpeedRatings',
            'FocalLength', 'Orientation']


def fetch_url(url, timeout=20):
    if not url.lower().startswith(('http://', 'https://')):
        raise ValueError('URL gambar harus http(s)')
    resp = requests.get(url, headers=UA, timeout=timeout, stream=True)
    resp.raise_for_status()
    ctype = resp.headers.get('Content-Type', '')
    if ctype and not ctype.startswith('image/') and 'octet-stream' not in ctype:
        raise ValueError(f'URL bukan gambar ({ctype})')
    data = resp.raw.read(MAX_BYTES + 1, decode_content=True)
    if len(data) > MAX_BYTES:
        raise ValueError('Gambar lebih dari 15 MB')
    return data


def _ratio(value):
    try:
        return float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        try:
            num, den = value
            return float(num) / float(den) if den else 0.0
        except (TypeError, ValueError):
            return None


def _dms_to_decimal(dms, ref):
    try:
        d, m, s = (_ratio(x) for x in dms)
    except (TypeError, ValueError):
        return None
    if None in (d, m, s):
        return None
    value = d + m / 60 + s / 3600
    if ref in ('S', 'W', b'S', b'W'):
        value = -value
    return round(value, 7)


def _clean(value):
    if isinstance(value, bytes):
        for enc in ('utf-16-le', 'utf-8', 'latin-1'):
            try:
                text = value.decode(enc).strip('\x00').strip()
                if text and text.isprintable():
                    return text[:300]
            except UnicodeDecodeError:
                continue
        return f'<{len(value)} bytes>'
    if isinstance(value, tuple):
        return ', '.join(str(_clean(v)) for v in value)[:300]
    try:
        f = float(value)
        if not isinstance(value, (int, str)):
            return round(f, 4)
    except (TypeError, ValueError):
        pass
    return str(value)[:300]


def pillow_metadata(data):
    from PIL import ExifTags, Image

    img = Image.open(io.BytesIO(data))
    info = {
        'format': img.format, 'mode': img.mode, 'width': img.width, 'height': img.height,
        'frames': getattr(img, 'n_frames', 1),
    }
    exif = img.getexif()
    tags = {}
    for tag_id, value in exif.items():
        tags[ExifTags.TAGS.get(tag_id, str(tag_id))] = _clean(value)
    try:
        for tag_id, value in exif.get_ifd(ExifTags.IFD.Exif).items():
            tags[ExifTags.TAGS.get(tag_id, str(tag_id))] = _clean(value)
    except (KeyError, AttributeError):
        pass

    gps = None
    try:
        gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo)
    except (KeyError, AttributeError):
        gps_ifd = {}
    if gps_ifd:
        g = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}
        lat = _dms_to_decimal(g.get('GPSLatitude'), g.get('GPSLatitudeRef')) if g.get('GPSLatitude') else None
        lng = _dms_to_decimal(g.get('GPSLongitude'), g.get('GPSLongitudeRef')) if g.get('GPSLongitude') else None
        if lat is not None and lng is not None and (lat or lng):
            alt = _ratio(g.get('GPSAltitude')) if g.get('GPSAltitude') is not None else None
            gps = {'lat': lat, 'lng': lng, 'altitude': round(alt, 1) if alt is not None else None,
                   'timestamp': f'{_clean(g.get("GPSDateStamp", ""))} {_clean(g.get("GPSTimeStamp", ""))}'.strip(),
                   'direction': _ratio(g.get('GPSImgDirection')) if g.get('GPSImgDirection') is not None else None}

    return img, info, tags, gps


def perceptual_hashes(img):
    """Average hash and difference hash (64-bit, hex) for near-duplicate search."""
    from PIL import Image

    gray = img.convert('L')
    small = gray.resize((8, 8), Image.Resampling.LANCZOS)
    px = list(small.getdata())
    avg = sum(px) / len(px)
    ahash = int(''.join('1' if p >= avg else '0' for p in px), 2)
    wide = gray.resize((9, 8), Image.Resampling.LANCZOS)
    w = list(wide.getdata())
    bits = ''.join('1' if w[r * 9 + c] > w[r * 9 + c + 1] else '0' for r in range(8) for c in range(8))
    return {'ahash': f'{ahash:016x}', 'dhash': f'{int(bits, 2):016x}'}


def exiftool_metadata(data):
    """Full metadata via exiftool when installed (XMP, IPTC, MakerNotes …)."""
    binary = shutil.which('exiftool')
    if not binary:
        return None
    try:
        proc = subprocess.run([binary, '-json', '-G1', '-n', '-'], input=data, capture_output=True,
                              timeout=20, check=False)
        rows = json.loads(proc.stdout or b'[]')
    except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
        return None
    if not rows:
        return None
    skip = ('SourceFile', 'ExifTool:', 'System:', 'File:Directory', 'File:FileName')
    return {k: (str(v)[:300] if not isinstance(v, (int, float)) else v)
            for k, v in rows[0].items() if not k.startswith(skip) and not k.endswith('ThumbnailImage')}


def ocr_backend():
    if shutil.which(os.environ.get('MOTOKU_TESSERACT_PATH', 'tesseract')):
        return 'tesseract'
    return None


def ocr(img, langs=None):
    """Return recognised text (or None when Tesseract is not installed)."""
    if not ocr_backend():
        return None
    langs = langs or os.environ.get('MOTOKU_OCR_LANGS', 'eng+ind')
    buf = io.BytesIO()
    img.convert('RGB').save(buf, format='PNG')
    binary = shutil.which(os.environ.get('MOTOKU_TESSERACT_PATH', 'tesseract'))
    for lang in (langs, 'eng'):
        try:
            proc = subprocess.run([binary, 'stdin', 'stdout', '-l', lang], input=buf.getvalue(),
                                  capture_output=True, timeout=60, check=False)
        except (subprocess.TimeoutExpired, OSError):
            return None
        if proc.returncode == 0:
            return proc.stdout.decode('utf-8', errors='replace').strip()
    return None


def reverse_search_links(image_url=None):
    pages = [
        ('Google Lens', 'https://lens.google.com/', 'https://lens.google.com/uploadbyurl?url={u}'),
        ('Bing Visual Search', 'https://www.bing.com/visualsearch', 'https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{u}'),
        ('Yandex Images', 'https://yandex.com/images/', 'https://yandex.com/images/search?rpt=imageview&url={u}'),
        ('TinEye', 'https://tineye.com/', 'https://tineye.com/search?url={u}'),
        ('PimEyes (wajah)', 'https://pimeyes.com/en', None),
        ('Baidu Images', 'https://graph.baidu.com/pcpage/index?tpl_from=pc', None),
    ]
    out = []
    for label, upload_page, template in pages:
        if image_url and template:
            out.append({'label': label, 'url': template.format(u=quote(image_url, safe='')), 'direct': True})
        else:
            out.append({'label': label, 'url': upload_page, 'direct': False})
    return out


def analyse(data, filename=None, image_url=None, with_ocr=True):
    if not data:
        raise ValueError('File kosong')
    if len(data) > MAX_BYTES:
        raise ValueError('Gambar lebih dari 15 MB')
    try:
        img, info, tags, gps = pillow_metadata(data)
    except Exception as e:
        raise ValueError(f'Bukan file gambar yang didukung ({type(e).__name__})')

    key = {k: tags[k] for k in KEY_TAGS if k in tags}
    report = {
        'filename': filename,
        'image_url': image_url,
        'size_bytes': len(data),
        'info': info,
        'hashes': {'md5': hashlib.md5(data).hexdigest(), 'sha1': hashlib.sha1(data).hexdigest(),
                   'sha256': hashlib.sha256(data).hexdigest(), **perceptual_hashes(img)},
        'exif_key': key,
        'exif_all': tags,
        'exiftool': exiftool_metadata(data),
        'gps': gps,
        'ocr': ocr(img) if with_ocr else None,
        'ocr_available': bool(ocr_backend()),
        'reverse_search': reverse_search_links(image_url),
        'warnings': [],
    }
    if not tags:
        report['warnings'].append('Tidak ada EXIF — kemungkinan sudah dihapus (umum pada gambar dari media sosial/WhatsApp).')
    if 'Software' in key and any(s in str(key['Software']).lower() for s in ('photoshop', 'gimp', 'lightroom', 'snapseed', 'canva')):
        report['warnings'].append(f'Gambar diproses dengan editor: {key["Software"]}')
    if key.get('DateTime') and key.get('DateTimeOriginal') and key['DateTime'] != key['DateTimeOriginal']:
        report['warnings'].append('DateTime berbeda dengan DateTimeOriginal — file pernah dimodifikasi setelah dipotret.')
    if gps:
        report['warnings'].append('Gambar mengandung koordinat GPS lokasi pengambilan.')
    return report
