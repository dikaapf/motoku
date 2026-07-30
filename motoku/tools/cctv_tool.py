import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
DB_FILE = os.path.join(DATA_DIR, 'cctv_indonesia.json')

CCTV_INDONESIA_BASE = 'https://cctvindonesia.id'

PROVINCE_CODE_MAP = {}  # populated lazily

COMMON_PORTS = [80, 8080, 443, 554, 8554, 8000, 9090, 8888]
COMMON_PATHS = [
    '/', '/login', '/video', '/stream', '/cgi-bin/',
    '/img/', '/mjpeg/', '/snapshot', '/cgi-bin/snapshot.cgi',
    '/view/', '/live', '/cam', '/image', '/mjpeg/video.mjpeg',
]
CAMERA_SIGNATURES = [
    'ip camera', 'dvr', 'hikvision', 'dahua', 'webcam',
    'camera', 'axis', 'netcam', 'viewnetcam', 'vivotek',
    'netwave', 'mobotix', 'arecont', 'dlink', 'linksys',
    'panasonic', 'sony', 'toshiba', 'geovision', 'novo',
]


def fetch_provinces():
    """Scrape province list from wilayah.php, return list of (code, name)."""
    try:
        resp = requests.get(f'{CCTV_INDONESIA_BASE}/wilayah.php', timeout=15)
        resp.raise_for_status()
        html = resp.text
        pattern = r'/provinsi\.php\?kode=(\d+)[^>]*>([^<]+)</a>'
        matches = re.findall(pattern, html)
        provinces = [(code, name.strip()) for code, name in matches]
        PROVINCE_CODE_MAP.update(dict(provinces))
        return provinces
    except Exception as e:
        raise RuntimeError(f'Gagal mengambil daftar provinsi: {e}')


def fetch_cameras_by_province(prov_code):
    """Fetch camera list for a province code from the CCTV Indonesia API."""
    try:
        resp = requests.get(
            f'{CCTV_INDONESIA_BASE}/api/cctv.php?prov={prov_code}',
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        province_name = PROVINCE_CODE_MAP.get(prov_code, f'Provinsi {prov_code}')
        cameras = []
        for c in data.get('cctv', []):
            cameras.append({
                'id': f'cctvindonesia_{c["id"]}',
                'name': c.get('nama', 'Unknown'),
                'city': c.get('kabupaten', '-'),
                'district': c.get('kecamatan', ''),
                'province': province_name,
                'lat': c.get('lat'),
                'lng': c.get('lng'),
                'source': c.get('sumber', 'CCTV Indonesia'),
                'source_url': c.get('sumber_url', ''),
                'type': c.get('stream_type', 'hls'),
                'url': c.get('stream_url', ''),
                'status': 'active' if c.get('status') == 'aktif' else 'inactive',
                'kode_kabupaten': c.get('kode_kabupaten', ''),
            })
        return cameras
    except Exception as e:
        raise RuntimeError(f'Gagal mengambil CCTV provinsi {prov_code}: {e}')


def sync_from_cctv_indonesia(callback=None):
    """Sync all cameras from cctvindonesia.id into local database.

    callback(step, total, message) is called for progress updates.
    Returns (added, updated, total, errors).
    """
    added = updated = errors = 0
    provinces = fetch_provinces()
    all_new = []

    if callback:
        callback(0, len(provinces), f'Mendapatkan {len(provinces)} provinsi...')

    for i, (code, name) in enumerate(provinces):
        prov_cameras = []
        try:
            prov_cameras = fetch_cameras_by_province(code)
        except Exception as e:
            errors += 1
            if callback:
                callback(i + 1, len(provinces),
                         f'Gagal provinsi {name}: {e}')
            continue

        all_new.extend(prov_cameras)
        if callback:
            callback(i + 1, len(provinces),
                     f'{name}: {len(prov_cameras)} kamera')

    existing = load_cameras()
    existing_ids = {c['id'] for c in existing}
    new_ids = {c['id'] for c in all_new}

    keep_existing = [c for c in existing if c['id'] not in new_ids]
    for c in all_new:
        if c['id'] in existing_ids:
            updated += 1
        else:
            added += 1

    merged = keep_existing + all_new
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(DB_FILE, 'w') as f:
        json.dump({'cameras': merged}, f, indent=2)

    if callback:
        callback(len(provinces), len(provinces),
                 f'Selesai! Ditambahkan {added}, diperbarui {updated}, '
                 f'total {len(merged)} kamera, {errors} error.')

    return added, updated, len(merged), errors


def load_cameras():
    if not os.path.exists(DB_FILE):
        return []
    with open(DB_FILE) as f:
        data = json.load(f)
    return data.get('cameras', [])


def get_cities(cameras=None):
    if cameras is None:
        cameras = load_cameras()
    cities = {}
    for cam in cameras:
        city = cam.get('city', 'Unknown')
        if city not in cities:
            cities[city] = 0
        cities[city] += 1
    return cities


def get_camera(cam_id):
    cameras = load_cameras()
    for cam in cameras:
        if cam['id'] == cam_id:
            return cam
    return None


def _check_path(ip, port, path, timeout=3):
    import requests
    url = f'http://{ip}:{port}{path}'
    if port == 443:
        url = f'https://{ip}{path}'
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=False)
        text = resp.text.lower()
        server = resp.headers.get('Server', '').lower()
        for sig in CAMERA_SIGNATURES:
            if sig in text or sig in server:
                return {
                    'url': url,
                    'port': port,
                    'path': path,
                    'signature': sig,
                    'status': resp.status_code,
                    'server': resp.headers.get('Server', ''),
                }
        if resp.status_code == 200 and len(text) > 50 and len(text) < 50000:
            return {
                'url': url,
                'port': port,
                'path': path,
                'signature': 'unknown',
                'status': resp.status_code,
                'server': resp.headers.get('Server', ''),
            }
    except:
        pass
    return None


def _scan_target(target, timeout=3):
    import socket
    results = []
    try:
        ip = socket.gethostbyname(target)
    except:
        ip = target

    def check(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            r = sock.connect_ex((ip, port))
            if r == 0:
                for path in COMMON_PATHS:
                    result = _check_path(ip, port, path, timeout)
                    if result:
                        results.append(result)
                        break
        except:
            pass
        finally:
            sock.close()

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check, p) for p in COMMON_PORTS]
        for f in as_completed(futures):
            pass

    return results


def scan(target, timeout=3):
    results = _scan_target(target.strip(), timeout)
    return results


def save_camera(cam_data):
    cameras = load_cameras()
    for i, cam in enumerate(cameras):
        if cam['id'] == cam_data['id']:
            cameras[i] = cam_data
            break
    else:
        cameras.append(cam_data)
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(DB_FILE, 'w') as f:
        json.dump({'cameras': cameras}, f, indent=2)
    return True
