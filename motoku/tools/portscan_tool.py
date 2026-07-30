import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


COMMON_PORTS = [
    (21, 'FTP'), (22, 'SSH'), (23, 'Telnet'), (25, 'SMTP'),
    (53, 'DNS'), (80, 'HTTP'), (110, 'POP3'), (143, 'IMAP'),
    (443, 'HTTPS'), (445, 'SMB'), (993, 'IMAPS'), (995, 'POP3S'),
    (1433, 'MSSQL'), (1521, 'Oracle'), (2049, 'NFS'),
    (3306, 'MySQL'), (3389, 'RDP'), (5432, 'PostgreSQL'),
    (5900, 'VNC'), (6379, 'Redis'), (8080, 'HTTP-Alt'),
    (8443, 'HTTPS-Alt'), (27017, 'MongoDB'),
]


def scan_port(host, port, service):
    try:
        ip = socket.gethostbyname(host)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            banner = _grab_banner(ip, port)
            return {'port': port, 'service': service, 'state': 'open', 'banner': banner}
    except Exception:
        pass
    return None


def _grab_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        return banner[:200] if banner else ''
    except Exception:
        return ''


def scan(host, ports=None):
    if ports is None:
        ports = COMMON_PORTS
    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_port, host, p, s): (p, s) for p, s in ports}
        for future in as_completed(futures):
            r = future.result()
            if r:
                results.append(r)
    results.sort(key=lambda x: x['port'])
    return results
