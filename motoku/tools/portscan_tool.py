"""Port scanner with nmap service detection and a TCP-connect fallback.

nmap is used when installed (``-sT -sV``, no root needed); otherwise a threaded
connect scan with banner grabbing runs. Every open port gets a risk rating
based on the exposed service.
"""

import os
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = [
    (21, 'ftp'), (22, 'ssh'), (23, 'telnet'), (25, 'smtp'), (53, 'domain'),
    (80, 'http'), (110, 'pop3'), (111, 'rpcbind'), (135, 'msrpc'), (139, 'netbios-ssn'),
    (143, 'imap'), (161, 'snmp'), (389, 'ldap'), (443, 'https'), (445, 'microsoft-ds'),
    (465, 'smtps'), (587, 'submission'), (631, 'ipp'), (873, 'rsync'), (993, 'imaps'),
    (995, 'pop3s'), (1080, 'socks'), (1433, 'ms-sql-s'), (1521, 'oracle'),
    (1883, 'mqtt'), (2049, 'nfs'), (2375, 'docker'), (2376, 'docker-tls'),
    (3000, 'http-alt'), (3306, 'mysql'), (3389, 'ms-wbt-server'), (5000, 'http-alt'),
    (5432, 'postgresql'), (5601, 'kibana'), (5672, 'amqp'), (5900, 'vnc'),
    (5985, 'winrm'), (6379, 'redis'), (6443, 'kubernetes'), (8000, 'http-alt'),
    (8080, 'http-proxy'), (8081, 'http-alt'), (8443, 'https-alt'), (8888, 'http-alt'),
    (9000, 'http-alt'), (9090, 'http-alt'), (9200, 'elasticsearch'), (9300, 'elasticsearch'),
    (10250, 'kubelet'), (11211, 'memcached'), (15672, 'rabbitmq-mgmt'), (27017, 'mongodb'),
]
PORT_NAMES = dict(COMMON_PORTS)

# port -> (risk, reason)
RISK_RULES = {
    23: ('critical', 'Telnet mengirim kredensial tanpa enkripsi'),
    2375: ('critical', 'Docker API tanpa TLS = remote code execution'),
    10250: ('critical', 'Kubelet API terekspos'),
    6379: ('high', 'Redis sering tanpa autentikasi'),
    11211: ('high', 'Memcached terbuka (amplifikasi DDoS, kebocoran data)'),
    27017: ('high', 'MongoDB terekspos ke internet'),
    9200: ('high', 'Elasticsearch terekspos (sering tanpa auth)'),
    9300: ('high', 'Elasticsearch transport terekspos'),
    445: ('high', 'SMB terekspos (EternalBlue, ransomware)'),
    139: ('high', 'NetBIOS/SMB terekspos'),
    135: ('high', 'MS-RPC terekspos'),
    3389: ('high', 'RDP terekspos (brute force, BlueKeep)'),
    5900: ('high', 'VNC terekspos'),
    5985: ('high', 'WinRM terekspos'),
    2049: ('high', 'NFS terekspos'),
    873: ('high', 'rsync terekspos'),
    3306: ('medium', 'Database MySQL dapat dijangkau publik'),
    5432: ('medium', 'Database PostgreSQL dapat dijangkau publik'),
    1433: ('medium', 'Database MSSQL dapat dijangkau publik'),
    1521: ('medium', 'Database Oracle dapat dijangkau publik'),
    21: ('medium', 'FTP tanpa enkripsi'),
    161: ('medium', 'SNMP dapat membocorkan konfigurasi'),
    389: ('medium', 'LDAP tanpa enkripsi'),
    1883: ('medium', 'MQTT broker terbuka'),
    5601: ('medium', 'Kibana terekspos'),
    15672: ('medium', 'Panel RabbitMQ terekspos'),
    6443: ('medium', 'Kubernetes API terekspos'),
    111: ('medium', 'rpcbind terekspos'),
    1080: ('medium', 'Proxy SOCKS terbuka'),
    110: ('low', 'POP3 tanpa enkripsi'),
    143: ('low', 'IMAP tanpa enkripsi'),
    22: ('low', 'SSH: pastikan hanya key-based auth'),
    25: ('info', 'SMTP (normal untuk mail server)'),
    53: ('info', 'DNS'),
    80: ('info', 'HTTP'),
    443: ('info', 'HTTPS'),
}
RISK_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
INSECURE_PRODUCTS = ('vsftpd 2.3.4', 'proftpd 1.3.3', 'openssh 4.', 'openssh 5.', 'openssh 6.',
                     'apache httpd 2.2', 'microsoft iis httpd 6', 'nginx 1.0', 'nginx 1.1')


def nmap_available():
    return shutil.which(os.environ.get('MOTOKU_NMAP_PATH', 'nmap')) is not None


def rate(port, service='', product=''):
    risk, reason = RISK_RULES.get(port, ('low', 'Layanan tidak umum terbuka ke publik'))
    text = f'{product}'.lower()
    for marker in INSECURE_PRODUCTS:
        if marker in text:
            risk = 'high' if RISK_ORDER[risk] > RISK_ORDER['high'] else risk
            reason += f' — versi usang ({product})'
            break
    if service and 'http' in service and port not in (80, 443) and risk == 'low':
        reason = 'Panel/web service di port non-standar'
    return risk, reason


def _resolve(host):
    try:
        return socket.gethostbyname(host)
    except OSError:
        raise ValueError(f'Host {host} tidak bisa di-resolve')


def parse_nmap_xml(xml_text):
    root = ET.fromstring(xml_text)
    results = []
    for port_el in root.iter('port'):
        state = port_el.find('state')
        if state is None or state.get('state') != 'open':
            continue
        svc = port_el.find('service')
        port = int(port_el.get('portid'))
        service = svc.get('name', '') if svc is not None else ''
        product = ' '.join(filter(None, [
            svc.get('product', '') if svc is not None else '',
            svc.get('version', '') if svc is not None else '',
        ])).strip()
        extra = svc.get('extrainfo', '') if svc is not None else ''
        risk, reason = rate(port, service, product)
        results.append({
            'port': port,
            'protocol': port_el.get('protocol', 'tcp'),
            'state': 'open',
            'service': service or PORT_NAMES.get(port, ''),
            'product': product,
            'extra': extra,
            'cpe': [c.text for c in port_el.iter('cpe')],
            'banner': '',
            'risk': risk,
            'risk_reason': reason,
        })
    return results


def nmap_scan(host, ports, timeout=600):
    port_arg = ','.join(str(p) for p in ports)
    cmd = [os.environ.get('MOTOKU_NMAP_PATH', 'nmap'), '-sT', '-sV', '--version-light', '-Pn',
           '-T4', '--open', '-oX', '-', '-p', port_arg, host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise ValueError('nmap timeout')
    if proc.returncode != 0 or '<nmaprun' not in proc.stdout:
        raise ValueError(f'nmap gagal: {proc.stderr.strip()[:200]}')
    return parse_nmap_xml(proc.stdout)


def _grab_banner(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            if port in (80, 8080, 8000, 8081, 8888, 3000, 5000, 9000, 9090):
                s.sendall(b'HEAD / HTTP/1.0\r\nHost: x\r\n\r\n')
            banner = s.recv(512).decode('utf-8', errors='ignore').strip()
            return banner[:200]
    except OSError:
        return ''


def _connect(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=1.5):
            return True
    except OSError:
        return False


def connect_scan(host, ports, progress=None):
    ip = _resolve(host)
    results = []
    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(_connect, ip, p): p for p in ports}
        for i, fut in enumerate(as_completed(futures), 1):
            port = futures[fut]
            if fut.result():
                banner = _grab_banner(ip, port)
                service = PORT_NAMES.get(port, '')
                risk, reason = rate(port, service, banner)
                results.append({'port': port, 'protocol': 'tcp', 'state': 'open',
                                'service': service, 'product': '', 'extra': '', 'cpe': [],
                                'banner': banner, 'risk': risk, 'risk_reason': reason})
            if progress and i % 10 == 0:
                progress(i, len(ports))
    return results


def parse_ports(spec):
    """'top' | '22,80,443' | '1-1024' → list of ints."""
    spec = (spec or 'top').strip().lower()
    if spec in ('top', 'common', ''):
        return [p for p, _ in COMMON_PORTS]
    ports = set()
    for part in spec.split(','):
        part = part.strip()
        if '-' in part:
            a, b = part.split('-', 1)
            a, b = int(a), int(b)
            if not (1 <= a <= b <= 65535):
                raise ValueError('Range port tidak valid')
            ports.update(range(a, b + 1))
        elif part:
            p = int(part)
            if not 1 <= p <= 65535:
                raise ValueError('Port tidak valid')
            ports.add(p)
    if len(ports) > 5000:
        raise ValueError('Maksimal 5000 port per scan')
    return sorted(ports)


def scan(host, ports=None, engine='auto', progress=None):
    host = (host or '').strip().lower()
    host = host.split('://')[-1].split('/')[0].split(':')[0]
    if not host:
        raise ValueError('Host kosong')
    ports = parse_ports(ports) if isinstance(ports, str) or ports is None else ports
    ip = _resolve(host)

    use_nmap = engine == 'nmap' or (engine == 'auto' and nmap_available())
    used = 'connect'
    if use_nmap:
        try:
            results = nmap_scan(host, ports)
            used = 'nmap'
        except ValueError:
            results = connect_scan(host, ports, progress)
    else:
        results = connect_scan(host, ports, progress)

    results.sort(key=lambda r: r['port'])
    summary = {level: 0 for level in RISK_ORDER}
    for r in results:
        summary[r['risk']] += 1
    worst = min((r['risk'] for r in results), key=lambda x: RISK_ORDER[x], default='info')
    return {
        'host': host,
        'ip': ip,
        'engine': used,
        'ports_scanned': len(ports),
        'open': results,
        'summary': summary,
        'overall_risk': worst,
    }
