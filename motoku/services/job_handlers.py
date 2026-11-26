"""Job handler registrations. Imported by the app and by RQ workers."""

from services import jobs, recon
from tools import portscan_tool, subdomain_tool, takeover_tool, wmn_tool


@jobs.handler('recon', 'Recon domain lengkap')
def recon_job(ctx, domain, options=None):
    return recon.run(ctx, domain, options)


@jobs.handler('subdomain', 'Subdomain enumeration')
def subdomain_job(ctx, domain, takeover=True):
    data = subdomain_tool.enumerate_subdomains(domain, progress=lambda p, m: ctx.progress(p * 0.9, m))
    data['takeover'] = None
    if takeover:
        ctx.progress(90, 'Cek subdomain takeover')
        data['takeover'] = takeover_tool.scan(data['hosts'])
    vulnerable = {f['host'] for f in (data['takeover'] or {}).get('findings', [])}
    data['graph'] = subdomain_tool.build_graph(data, vulnerable)
    return data


@jobs.handler('portscan', 'Port scan')
def portscan_job(ctx, target, ports='top', engine='auto'):
    ctx.progress(5, f'Scan {target} ({ports})')
    return portscan_tool.scan(target, ports, engine,
                              progress=lambda i, n: ctx.progress(5 + 90 * i / n))


@jobs.handler('username', 'Username WhatsMyName')
def username_job(ctx, username, categories=None, include_nsfw=False):
    ctx.progress(5, f'Cek @{username} di situs WhatsMyName')
    return wmn_tool.search(username, categories=categories or None, include_nsfw=include_nsfw,
                           progress=lambda p, m: ctx.progress(5 + p * 0.93, m))
