"""Declarations of every external data source used by the tools."""

from services.providers import register

HIBP = register(
    'hibp', ttl=6 * 3600, daily_quota=500, key_env='MOTOKU_HIBP_API_KEY',
    description='Have I Been Pwned — breach lookup per email',
    homepage='https://haveibeenpwned.com/API/Key',
)
EMAILREP = register(
    'emailrep.io', ttl=6 * 3600, daily_quota=10 * 24,
    description='Reputasi email (10 req/jam tanpa key)',
    homepage='https://emailrep.io',
)
GRAVATAR = register(
    'gravatar.com', ttl=24 * 3600,
    description='Profil publik Gravatar', homepage='https://gravatar.com',
)
RDAP = register(
    'rdap', ttl=12 * 3600,
    description='Registration Data Access Protocol (pengganti WHOIS)',
    homepage='https://rdap.org',
)
WHOIS = register(
    'whois', ttl=12 * 3600, description='WHOIS port 43 (fallback RDAP)',
)
WHATSMYNAME = register(
    'whatsmyname', ttl=6 * 3600,
    description='Dataset WhatsMyName (~600 situs) untuk username',
    homepage='https://github.com/WebBreacher/WhatsMyName',
)
HTTP_HEADERS = register(
    'http-headers', ttl=15 * 60, description='Fetch HTTP security header',
)
MTA_STS = register(
    'mta-sts', ttl=6 * 3600, description='Fetch policy MTA-STS (.well-known)',
)
DNS = register(
    'dns', ttl=15 * 60, description='Resolver DNS (dnspython)',
)

# ── S2: infra recon ──
CRTSH = register(
    'crt.sh', ttl=12 * 3600, daily_quota=300,
    description='Certificate Transparency (crt.sh)', homepage='https://crt.sh',
)
CERTSPOTTER = register(
    'certspotter', ttl=12 * 3600, daily_quota=100,
    description='CertSpotter CT API (100 query/jam tanpa key; key opsional)',
    homepage='https://sslmate.com/certspotter/api/',
)
OTX = register(
    'otx', ttl=12 * 3600, daily_quota=1000,
    description='AlienVault OTX passive DNS (key opsional)',
    homepage='https://otx.alienvault.com',
)
HACKERTARGET = register(
    'hackertarget', ttl=12 * 3600, daily_quota=50,
    description='HackerTarget hostsearch (50 query/hari gratis)',
    homepage='https://hackertarget.com/find-dns-host-records/',
)
WAYBACK = register(
    'wayback', ttl=24 * 3600, daily_quota=500,
    description='Internet Archive Wayback CDX API', homepage='https://web.archive.org',
)
URLSCAN = register(
    'urlscan', ttl=6 * 3600, daily_quota=100,
    description='urlscan.io search (key opsional menaikkan limit)', homepage='https://urlscan.io',
)
HTTP_PROBE = register(
    'http-probe', ttl=30 * 60, description='HTTP probe host (status, title, server)',
)
