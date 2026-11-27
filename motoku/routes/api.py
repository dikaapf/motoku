"""REST API v1 (token auth).

Authenticate with ``Authorization: Bearer mtk_...`` (or ``X-API-Key``).
Scopes: ``read`` (GET), ``write`` (case changes), ``scan`` (run tools/jobs).
"""

import functools

from flask import Blueprint, g, jsonify, render_template, request, url_for

from routes import current_actor
from services import api_tokens, casedb, detect, importer, jobs, report, watch

bp = Blueprint('api_v1', __name__, url_prefix='/api/v1')


def _token_from_request():
    header = request.headers.get('Authorization', '')
    if header.lower().startswith('bearer '):
        return header[7:].strip()
    return request.headers.get('X-API-Key', '').strip()


def require(scope):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            token = api_tokens.verify(_token_from_request())
            if token is None:
                return jsonify({'error': 'unauthorized', 'hint': 'Authorization: Bearer <token>'}), 401
            if scope not in token['scopes']:
                return jsonify({'error': 'forbidden', 'required_scope': scope}), 403
            g.api_token = token
            return func(*args, **kwargs)
        return wrapper
    return decorator


@bp.errorhandler(ValueError)
def value_error(e):
    return jsonify({'error': str(e)}), 400


def _tools():
    """Synchronous tools: name → (callable(value, body), description)."""
    from tools import (
        corporate_tool,
        cve_tool,
        dns_security,
        dns_tool,
        domain_tool,
        email_tool,
        geo_tool,
        phone_tool,
        social_tool,
        threat_intel,
        tls_scan,
        web_security,
    )
    return {
        'dns': (lambda v, b: dns_tool.resolve_all(v), 'DNS records'),
        'dns-security': (lambda v, b: dns_security.analyse(v), 'SPF/DKIM/DMARC/DNSSEC grade'),
        'web-security': (lambda v, b: web_security.analyse(v), 'Security headers + TLS'),
        'domain': (lambda v, b: domain_tool.lookup(v), 'RDAP/WHOIS'),
        'email': (lambda v, b: email_tool.investigate(v, smtp_check=bool(b.get('smtp'))), 'Email intelligence'),
        'intel': (lambda v, b: threat_intel.lookup(v), 'Threat intel (IP/domain/URL/hash)'),
        'cve': (lambda v, b: cve_tool.search(v), 'CVE / CPE / produk versi'),
        'tls': (lambda v, b: tls_scan.scan(v), 'TLS scan + CT'),
        'phone': (lambda v, b: phone_tool.track(v), 'Phone intel'),
        'geo': (lambda v, b: geo_tool.investigate(v, tz_offset=b.get('tz')), 'Geo intel'),
        'social': (lambda v, b: social_tool.lookup(v), 'Profil sosial'),
        'corporate': (lambda v, b: corporate_tool.search(v), 'GLEIF/ORCID/OpenAlex'),
    }


TOOL_ENDPOINT_NAMES = {'dns': 'dns', 'dns-security': 'dns_security_page', 'web-security': 'web_security_page',
                       'domain': 'domain', 'email': 'email', 'intel': 'intel', 'cve': 'cve', 'tls': 'tls_page',
                       'phone': 'phone', 'geo': 'geo', 'social': 'social', 'corporate': 'corporate'}


@bp.route('')
def root():
    return jsonify({'name': 'Motoku OSINT API', 'version': 'v1', 'docs': url_for('api_v1.docs', _external=True)})


@bp.route('/docs')
def docs():
    return render_template('api_docs.html', tools=_tools(), job_kinds=jobs.handlers())


@bp.route('/me')
@require('read')
def me():
    t = g.api_token
    return jsonify({'name': t['name'], 'scopes': t['scopes'], 'prefix': t['prefix']})


@bp.route('/detect')
@require('read')
def detect_route():
    return jsonify(detect.routes_for(request.args.get('q', '')))


@bp.route('/tools')
@require('read')
def list_tools():
    return jsonify({name: desc for name, (_, desc) in _tools().items()})


@bp.route('/tools/<name>', methods=['POST'])
@require('scan')
def run_tool(name):
    tools = _tools()
    if name not in tools:
        return jsonify({'error': f'tool tidak dikenal: {name}', 'available': sorted(tools)}), 404
    body = request.get_json(silent=True) or {}
    value = (body.get('value') or body.get('q') or '').strip()
    if not value:
        return jsonify({'error': 'field "value" wajib'}), 400
    result = tools[name][0](value, body)
    out = {'tool': name, 'value': value, 'result': result}
    if body.get('case_id'):
        out['case_import'] = importer.import_result(body['case_id'], TOOL_ENDPOINT_NAMES.get(name, name), result,
                                                    current_actor(), label=value)
    return jsonify(out)


@bp.route('/jobs', methods=['POST'])
@require('scan')
def create_job():
    body = request.get_json(silent=True) or {}
    kind = body.get('kind')
    params = body.get('params') or {}
    if kind not in jobs.handlers() or kind == 'watch':
        return jsonify({'error': 'kind tidak valid', 'available': sorted(k for k in jobs.handlers() if k != 'watch')}), 400
    if kind == 'recon' and body.get('case_id'):
        params['case_id'] = body['case_id']
        params['actor'] = current_actor()
    target = body.get('target') or next(iter(params.values()), '')
    job_id = jobs.enqueue(kind, str(target)[:200], params)
    return jsonify({'job_id': job_id, 'status_url': url_for('api_v1.get_job', job_id=job_id, _external=True),
                    'events_url': url_for('api_job_events', job_id=job_id, _external=True)}), 202


@bp.route('/jobs/<job_id>')
@require('read')
def get_job(job_id):
    job = jobs.get(job_id)
    if job is None:
        return jsonify({'error': 'not found'}), 404
    return jsonify(jobs.public_view(job, include_result=request.args.get('result', '1') == '1'))


@bp.route('/cases', methods=['GET', 'POST'])
@require('read')
def cases():
    if request.method == 'POST':
        if 'write' not in g.api_token['scopes']:
            return jsonify({'error': 'forbidden', 'required_scope': 'write'}), 403
        body = request.get_json(silent=True) or {}
        case_id = casedb.create_case(body.get('title'), body.get('description', ''), body.get('tags'),
                                     current_actor())
        return jsonify(casedb.get_case(case_id)), 201
    return jsonify(casedb.list_cases(request.args.get('status')))


@bp.route('/cases/<case_id>')
@require('read')
def case_detail(case_id):
    case = casedb.get_case(case_id)
    if not case:
        return jsonify({'error': 'not found'}), 404
    return jsonify({**case, 'entities': casedb.list_entities(case_id), 'findings': casedb.list_findings(case_id),
                    'relations': casedb.list_relations(case_id), 'custody': casedb.verify_custody(case_id)})


@bp.route('/cases/<case_id>/entities', methods=['POST'])
@require('write')
def case_add_entity(case_id):
    body = request.get_json(silent=True) or {}
    eid = casedb.add_entity(case_id, body.get('type', 'other'), body.get('value', ''), body.get('label'),
                            body.get('data'), 'api', current_actor(), body.get('tags'))
    return jsonify({'id': eid}), 201


@bp.route('/cases/<case_id>/notes', methods=['POST'])
@require('write')
def case_add_note(case_id):
    body = request.get_json(silent=True) or {}
    return jsonify({'id': casedb.add_note(case_id, body.get('body', ''), current_actor())}), 201


@bp.route('/cases/<case_id>/findings', methods=['POST'])
@require('write')
def case_add_finding(case_id):
    body = request.get_json(silent=True) or {}
    if not body.get('title'):
        return jsonify({'error': 'title wajib'}), 400
    created = casedb.create_finding(case_id, body.get('severity', 'medium'), body['title'], body.get('detail', ''),
                                    current_actor())
    return jsonify({'created': created}), 201


@bp.route('/cases/<case_id>/import', methods=['POST'])
@require('write')
def case_import(case_id):
    body = request.get_json(silent=True) or {}
    if body.get('job_id'):
        job = jobs.get(body['job_id'])
        if job is None:
            return jsonify({'error': 'job tidak ditemukan'}), 404
        return jsonify(importer.import_job(case_id, job, current_actor()))
    if not isinstance(body.get('data'), (dict, list)):
        return jsonify({'error': 'field "data" (hasil tool) atau "job_id" wajib'}), 400
    return jsonify(importer.import_result(case_id, body.get('tool', 'generic'), body['data'], current_actor(),
                                          body.get('label')))


@bp.route('/cases/<case_id>/report')
@require('read')
def case_report(case_id):
    if not casedb.get_case(case_id):
        return jsonify({'error': 'not found'}), 404
    fmt = request.args.get('format', 'json')
    ctx = report.build(case_id)
    if fmt == 'md':
        body = report.to_markdown(ctx)
        casedb.log_export(case_id, 'md', report.digest(body), current_actor())
        return body, 200, {'Content-Type': 'text/markdown; charset=utf-8'}
    casedb.log_export(case_id, 'json', report.digest(report.to_json(ctx)), current_actor())
    return jsonify(ctx)


@bp.route('/watchlist', methods=['GET', 'POST'])
@require('read')
def watchlist():
    if request.method == 'POST':
        if 'write' not in g.api_token['scopes']:
            return jsonify({'error': 'forbidden', 'required_scope': 'write'}), 403
        body = request.get_json(silent=True) or {}
        wid = watch.add(body.get('type'), body.get('target'), body.get('checks'), body.get('interval_min', 1440),
                        body.get('case_id'), body.get('label'), body.get('notify'))
        return jsonify(watch.get(wid)), 201
    return jsonify(watch.list_all(request.args.get('case_id')))


@bp.route('/alerts')
@require('read')
def alerts():
    return jsonify(watch.list_alerts(request.args.get('limit', 100, type=int), request.args.get('case_id'),
                                     request.args.get('unacked') == '1'))
