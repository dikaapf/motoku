"""Declarations of every external data source used by the tools."""

from services.providers import register

HIBP = register(
    'hibp', category='Email', ttl=6 * 3600, daily_quota=500, key_env='MOTOKU_HIBP_API_KEY',
    description='Have I Been Pwned — breach lookup per email',
    homepage='https://haveibeenpwned.com/API/Key',
)
EMAILREP = register(
    'emailrep.io', category='Email', ttl=6 * 3600, daily_quota=10 * 24,
    description='Reputasi email (10 req/jam tanpa key)',
    homepage='https://emailrep.io',
)
GRAVATAR = register(
    'gravatar.com', category='Email', ttl=24 * 3600,
    description='Profil publik Gravatar', homepage='https://gravatar.com',
)
RDAP = register(
    'rdap', category='Domain & DNS', ttl=12 * 3600,
    description='Registration Data Access Protocol (pengganti WHOIS)',
    homepage='https://rdap.org',
)
WHOIS = register(
    'whois', category='Domain & DNS', ttl=12 * 3600, description='WHOIS port 43 (fallback RDAP)',
)
WHATSMYNAME = register(
    'whatsmyname', category='Username', ttl=6 * 3600,
    description='Dataset WhatsMyName (~600 situs) untuk username',
    homepage='https://github.com/WebBreacher/WhatsMyName',
)
HTTP_HEADERS = register(
    'http-headers', category='Web', ttl=15 * 60, description='Fetch HTTP security header',
)
MTA_STS = register(
    'mta-sts', category='Domain & DNS', ttl=6 * 3600, description='Fetch policy MTA-STS (.well-known)',
)
DNS = register(
    'dns', category='Domain & DNS', ttl=15 * 60, description='Resolver DNS (dnspython)',
)

# ── S2: infra recon ──
CRTSH = register(
    'crt.sh', category='Recon', ttl=12 * 3600, daily_quota=300,
    description='Certificate Transparency (crt.sh)', homepage='https://crt.sh',
)
CERTSPOTTER = register(
    'certspotter', category='Recon', ttl=12 * 3600, daily_quota=100,
    key_env='MOTOKU_CERTSPOTTER_API_KEY', key_optional=True,
    description='CertSpotter CT API (100 query/jam tanpa key; key opsional)',
    homepage='https://sslmate.com/certspotter/api/',
)
OTX = register(
    'otx', category='Threat intel', ttl=12 * 3600, daily_quota=1000,
    key_env='MOTOKU_OTX_API_KEY', key_optional=True,
    description='AlienVault OTX passive DNS (key opsional)',
    homepage='https://otx.alienvault.com',
)
HACKERTARGET = register(
    'hackertarget', category='Recon', ttl=12 * 3600, daily_quota=50,
    description='HackerTarget hostsearch (50 query/hari gratis)',
    homepage='https://hackertarget.com/find-dns-host-records/',
)
WAYBACK = register(
    'wayback', category='Recon', ttl=24 * 3600, daily_quota=500,
    description='Internet Archive Wayback CDX API', homepage='https://web.archive.org',
)
URLSCAN = register(
    'urlscan', category='Recon', ttl=6 * 3600, daily_quota=100,
    key_env='MOTOKU_URLSCAN_API_KEY', key_optional=True,
    description='urlscan.io search (key opsional menaikkan limit)', homepage='https://urlscan.io',
)
HTTP_PROBE = register(
    'http-probe', category='Web', ttl=30 * 60, description='HTTP probe host (status, title, server)',
)

# ── S3: threat intel & enrichment ──
SHODAN = register('shodan', category='Attack surface', ttl=24 * 3600, daily_quota=100,
                  key_env='MOTOKU_SHODAN_API_KEY', description='Shodan host lookup (berbayar)',
                  homepage='https://account.shodan.io')
INTERNETDB = register('internetdb', category='Attack surface', ttl=24 * 3600, daily_quota=5000,
                      description='Shodan InternetDB: port, CPE, CVE per IP (gratis)',
                      homepage='https://internetdb.shodan.io')
CENSYS = register('censys', category='Attack surface', ttl=24 * 3600, daily_quota=8,
                  key_env='MOTOKU_CENSYS_API_SECRET',
                  description='Censys host lookup (butuh MOTOKU_CENSYS_API_ID + SECRET)',
                  homepage='https://search.censys.io/account/api')
FOFA = register('fofa', category='Attack surface', ttl=24 * 3600, daily_quota=100,
                key_env='MOTOKU_FOFA_API_KEY', description='FOFA search engine',
                homepage='https://fofa.info')
NETLAS = register('netlas', category='Attack surface', ttl=24 * 3600, daily_quota=50,
                  key_env='MOTOKU_NETLAS_API_KEY', description='Netlas host lookup',
                  homepage='https://app.netlas.io/profile/')
VIRUSTOTAL = register('virustotal', category='Reputasi', ttl=12 * 3600, daily_quota=500,
                      key_env='MOTOKU_VT_API_KEY', description='VirusTotal (500/hari, 4/menit gratis)',
                      homepage='https://www.virustotal.com/gui/my-apikey')
ABUSEIPDB = register('abuseipdb', category='Reputasi', ttl=12 * 3600, daily_quota=1000,
                     key_env='MOTOKU_ABUSEIPDB_API_KEY', description='AbuseIPDB laporan abuse IP',
                     homepage='https://www.abuseipdb.com/account/api')
GREYNOISE = register('greynoise', category='Reputasi', ttl=12 * 3600, daily_quota=50,
                     key_env='MOTOKU_GREYNOISE_API_KEY', key_optional=True,
                     description='GreyNoise community: scanner/benign/malicious',
                     homepage='https://viz.greynoise.io/account/api-key')
IPINFO = register('ipinfo', category='Network', ttl=24 * 3600, daily_quota=1500,
                  key_env='MOTOKU_IPINFO_TOKEN', key_optional=True,
                  description='IPinfo geolokasi & ASN', homepage='https://ipinfo.io/account/token')
RIPESTAT = register('ripestat', category='Network', ttl=24 * 3600,
                    description='RIPEstat prefix, ASN, holder (gratis)', homepage='https://stat.ripe.net')
URLHAUS = register('urlhaus', category='Malware & phishing', ttl=6 * 3600, daily_quota=2000,
                   key_env='MOTOKU_ABUSECH_API_KEY', description='abuse.ch URLhaus (Auth-Key gratis)',
                   homepage='https://auth.abuse.ch/')
MALWAREBAZAAR = register('malwarebazaar', category='Malware & phishing', ttl=24 * 3600, daily_quota=2000,
                         key_env='MOTOKU_ABUSECH_API_KEY', description='abuse.ch MalwareBazaar (hash)',
                         homepage='https://auth.abuse.ch/')
PHISHTANK = register('phishtank', category='Malware & phishing', ttl=6 * 3600, daily_quota=500,
                     key_env='MOTOKU_PHISHTANK_API_KEY', key_optional=True,
                     description='PhishTank cek URL phishing', homepage='https://phishtank.org')
SAFEBROWSING = register('safebrowsing', category='Malware & phishing', ttl=6 * 3600, daily_quota=10000,
                        key_env='MOTOKU_GSB_API_KEY', description='Google Safe Browsing v4',
                        homepage='https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com')
CVEDB = register('cvedb', category='Vulnerability', ttl=24 * 3600, daily_quota=5000,
                 description='Shodan CVEDB: CVE per CPE + CVSS/EPSS/KEV (gratis)',
                 homepage='https://cvedb.shodan.io')
NVD = register('nvd', category='Vulnerability', ttl=24 * 3600, daily_quota=2000,
               key_env='MOTOKU_NVD_API_KEY', key_optional=True,
               description='NIST NVD API 2.0 (fallback detail CVE)', homepage='https://nvd.nist.gov/developers')
EPSS = register('epss', category='Vulnerability', ttl=24 * 3600,
                description='FIRST EPSS skor probabilitas eksploitasi', homepage='https://www.first.org/epss/')
KEV = register('cisa-kev', category='Vulnerability', ttl=24 * 3600,
               description='CISA Known Exploited Vulnerabilities', homepage='https://www.cisa.gov/known-exploited-vulnerabilities-catalog')
GITHUB = register('github', category='Leak & cloud', ttl=6 * 3600, daily_quota=500,
                  key_env='MOTOKU_GITHUB_TOKEN', description='GitHub code search (butuh token)',
                  homepage='https://github.com/settings/tokens')
CLOUD_STORAGE = register('cloud-storage', category='Leak & cloud', ttl=6 * 3600,
                         description='Cek bucket publik S3 / GCS / Azure Blob')

# ── S4: people, image & geo ──
NOMINATIM = register('nominatim', category='Geo', ttl=7 * 86400, daily_quota=2000,
                     description='OpenStreetMap Nominatim (geocode, maks 1 req/detik)',
                     homepage='https://operations.osmfoundation.org/policies/nominatim/')
OVERPASS = register('overpass', category='Geo', ttl=24 * 3600, daily_quota=1000,
                    description='Overpass API: POI OpenStreetMap di sekitar titik',
                    homepage='https://wiki.openstreetmap.org/wiki/Overpass_API')
FIRMS = register('firms', category='Geo', ttl=3 * 3600, daily_quota=500, key_env='MOTOKU_FIRMS_MAP_KEY',
                 description='NASA FIRMS titik api aktif (MAP_KEY gratis)',
                 homepage='https://firms.modaps.eosdis.nasa.gov/api/map_key/')
GLEIF = register('gleif', category='Korporasi', ttl=7 * 86400,
                 description='GLEIF LEI: identitas badan hukum global (gratis)', homepage='https://www.gleif.org')
OPENCORPORATES = register('opencorporates', category='Korporasi', ttl=7 * 86400, daily_quota=200,
                          key_env='MOTOKU_OPENCORPORATES_TOKEN', description='OpenCorporates (butuh API token)',
                          homepage='https://opencorporates.com/api_accounts/new')
ORCID = register('orcid', category='Korporasi', ttl=7 * 86400,
                 description='ORCID registry peneliti (gratis)', homepage='https://orcid.org')
OPENALEX = register('openalex', category='Korporasi', ttl=7 * 86400,
                    description='OpenAlex: penulis, afiliasi, sitasi (pengganti Scholar)',
                    homepage='https://openalex.org')
GITHUB_PUBLIC = register('github-users', category='Sosial', ttl=6 * 3600, daily_quota=60 * 24,
                         key_env='MOTOKU_GITHUB_TOKEN', key_optional=True,
                         description='GitHub users API (60/jam tanpa token)', homepage='https://docs.github.com/rest/users')
REDDIT = register('reddit', category='Sosial', ttl=6 * 3600, daily_quota=1000,
                  key_env='MOTOKU_REDDIT_CLIENT_SECRET',
                  description='Reddit API (butuh MOTOKU_REDDIT_CLIENT_ID + SECRET, app "script")',
                  homepage='https://www.reddit.com/prefs/apps')
MASTODON = register('mastodon', category='Sosial', ttl=6 * 3600, description='Mastodon / fediverse lookup')
BLUESKY = register('bluesky', category='Sosial', ttl=6 * 3600, description='Bluesky public AppView API')
TELEGRAM = register('telegram', category='Sosial', ttl=6 * 3600, description='Halaman publik t.me')
TIKTOK = register('tiktok', category='Sosial', ttl=6 * 3600, daily_quota=300,
                  description='Profil publik TikTok (scraping, best-effort)')
