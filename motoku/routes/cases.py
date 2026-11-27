
from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from routes import current_actor
from services import casedb, importer, jobs, report, watch

bp = Blueprint('cases', __name__)


def _case_or_404(case_id):
    case = casedb.get_case(case_id)
    if not case:
        abort(404)
    return case


@bp.route('/cases', methods=['GET', 'POST'])
def index():
    error = None
    if request.method == 'POST':
        try:
            case_id = casedb.create_case(request.form.get('title'), request.form.get('description', ''),
                                         request.form.get('tags', ''), current_actor())
            return redirect(url_for('cases.detail', case_id=case_id))
        except ValueError as e:
            error = str(e)
    status = request.args.get('status') or None
    return render_template('cases.html', cases=casedb.list_cases(status), status=status, error=error)


@bp.route('/cases.json')
def list_json():
    return jsonify([{'id': c['id'], 'title': c['title'], 'status': c['status']}
                    for c in casedb.list_cases('open')])


@bp.route('/cases/<case_id>')
def detail(case_id):
    case = _case_or_404(case_id)
    entities = casedb.list_entities(case_id)
    return render_template(
        'case_detail.html', case=case, entities=entities, counts=casedb.entity_counts(case_id),
        findings=casedb.list_findings(case_id), notes=casedb.list_notes(case_id),
        attachments=casedb.list_attachments(case_id), events=casedb.list_events(case_id, 300),
        custody=casedb.verify_custody(case_id), watches=watch.list_all(case_id),
        alerts=watch.list_alerts(50, case_id), entity_types=list(casedb.ENTITY_TYPES),
        recent_jobs=[j for j in jobs_list() if j['status'] == 'finished'][:15],
        tab=request.args.get('tab', 'overview'), pdf_available=report.chromium_available())


def jobs_list():
    import db
    return db.list_jobs(limit=40)


@bp.route('/cases/<case_id>/update', methods=['POST'])
def update(case_id):
    _case_or_404(case_id)
    casedb.update_case(case_id, current_actor(), title=request.form.get('title'),
                       description=request.form.get('description'), status=request.form.get('status'),
                       tags=request.form.get('tags'))
    return redirect(url_for('cases.detail', case_id=case_id))


@bp.route('/cases/<case_id>/delete', methods=['POST'])
def delete(case_id):
    _case_or_404(case_id)
    if request.form.get('confirm') != case_id:
        abort(400, description='Ketik ID case untuk konfirmasi penghapusan')
    casedb.delete_case(case_id)
    return redirect(url_for('cases.index'))


@bp.route('/cases/<case_id>/entities', methods=['POST'])
def add_entity(case_id):
    _case_or_404(case_id)
    try:
        casedb.add_entity(case_id, request.form.get('type', 'other'), request.form.get('value', ''),
                          request.form.get('label') or None, actor=current_actor(), tags=request.form.get('tags'))
    except ValueError as e:
        flash(str(e))
    return redirect(url_for('cases.detail', case_id=case_id, tab='entities'))


@bp.route('/cases/<case_id>/entities/<int:entity_id>/delete', methods=['POST'])
def delete_entity(case_id, entity_id):
    casedb.delete_entity(case_id, entity_id, current_actor())
    return redirect(url_for('cases.detail', case_id=case_id, tab='entities'))


@bp.route('/cases/<case_id>/findings', methods=['POST'])
def add_finding(case_id):
    _case_or_404(case_id)
    title = request.form.get('title', '').strip()
    if title:
        casedb.create_finding(case_id, request.form.get('severity', 'medium'), title,
                              request.form.get('detail', ''), current_actor())
    return redirect(url_for('cases.detail', case_id=case_id, tab='findings'))


@bp.route('/cases/<case_id>/findings/<int:finding_id>/status', methods=['POST'])
def finding_status(case_id, finding_id):
    casedb.set_finding_status(case_id, finding_id, request.form.get('status', 'open'), current_actor())
    return redirect(url_for('cases.detail', case_id=case_id, tab='findings'))


@bp.route('/cases/<case_id>/notes', methods=['POST'])
def add_note(case_id):
    _case_or_404(case_id)
    try:
        entity_id = request.form.get('entity_id', type=int)
        casedb.add_note(case_id, request.form.get('body', ''), current_actor(), entity_id)
    except ValueError as e:
        flash(str(e))
    return redirect(url_for('cases.detail', case_id=case_id, tab='notes'))


@bp.route('/cases/<case_id>/attachments', methods=['POST'])
def upload(case_id):
    _case_or_404(case_id)
    f = request.files.get('file')
    if f and f.filename:
        casedb.add_attachment(case_id, f.filename, f.read(), f.mimetype, request.form.get('note'), current_actor())
    return redirect(url_for('cases.detail', case_id=case_id, tab='attachments'))


@bp.route('/cases/<case_id>/attachments/<int:attachment_id>')
def download(case_id, attachment_id):
    meta, data = casedb.get_attachment(case_id, attachment_id, current_actor())
    if meta is None:
        abort(404)
    headers = {'Content-Disposition': f'attachment; filename="{meta["filename"]}"',
               'X-Content-SHA256': meta['sha256'], 'X-Integrity': 'ok' if meta['intact'] else 'MISMATCH'}
    return Response(data, mimetype='application/octet-stream', headers=headers)


@bp.route('/cases/<case_id>/import', methods=['POST'])
def import_result(case_id):
    """Import a tool result (JSON body: {tool, data, label}) or a finished job ({job_id})."""
    _case_or_404(case_id)
    body = request.get_json(silent=True) or {}
    job_id = body.get('job_id') or request.form.get('job_id')
    try:
        if job_id:
            job = jobs.get(job_id)
            if job is None:
                return jsonify({'error': 'job tidak ditemukan'}), 404
            stats = importer.import_job(case_id, job, current_actor())
        else:
            if not isinstance(body.get('data'), (dict, list)):
                return jsonify({'error': 'data hasil tidak ada'}), 400
            stats = importer.import_result(case_id, (body.get('tool') or 'generic')[:40], body['data'],
                                           current_actor(), body.get('label'))
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    if request.is_json:
        return jsonify({'ok': True, 'case_id': case_id, **stats,
                        'url': url_for('cases.detail', case_id=case_id)})
    return redirect(url_for('cases.detail', case_id=case_id))


@bp.route('/cases/<case_id>/graph.json')
def graph(case_id):
    _case_or_404(case_id)
    entities = casedb.list_entities(case_id)
    limit = request.args.get('cve_limit', 40, type=int)
    # Large recon cases can hold hundreds of CVEs; keep the most urgent ones
    # and fold the rest into one summary node so the graph stays readable.
    cves = sorted((e for e in entities if e['type'] == 'cve'),
                  key=lambda e: (e['data'].get('priority') or 'P9', not e['data'].get('kev'),
                                 -(e['data'].get('epss') or 0)))
    hidden = {e['id'] for e in cves[limit:]}
    entities = [e for e in entities if e['id'] not in hidden]
    nodes = []
    if hidden:
        nodes.append({'id': 'cve-more', 'label': f'+{len(hidden)} CVE lainnya', 'group': 'cve', 'shape': 'box',
                      'title': 'CVE prioritas lebih rendah disembunyikan (lihat tab Entity)',
                      'color': {'background': '#2a0d0d', 'border': '#ff3333'}, 'font': {'color': '#ff6666'}})
    for e in entities:
        icon, color = casedb.ENTITY_TYPES.get(e['type'], casedb.ENTITY_TYPES['other'])
        label = e['label'] if e['type'] in ('account', 'service', 'certificate') and e['label'] else e['value']
        nodes.append({'id': e['id'], 'label': label[:40], 'group': e['type'], 'title': f'{e["type"]}: {e["value"]}',
                      'color': {'background': '#0d1110', 'border': color}, 'font': {'color': color}})
    edges, folded = [], set()
    for r in casedb.list_relations(case_id):
        src = 'cve-more' if r['src_id'] in hidden else r['src_id']
        dst = 'cve-more' if r['dst_id'] in hidden else r['dst_id']
        if 'cve-more' in (src, dst):
            if (src, dst) in folded:
                continue
            folded.add((src, dst))
        edges.append({'from': src, 'to': dst, 'label': r['kind'], 'arrows': 'to'})
    return jsonify({'nodes': nodes, 'edges': edges, 'hidden': len(hidden)})


@bp.route('/cases/<case_id>/timeline.json')
def timeline(case_id):
    _case_or_404(case_id)
    return jsonify(casedb.list_events(case_id, 1000))


@bp.route('/cases/<case_id>/custody')
def custody(case_id):
    case = _case_or_404(case_id)
    return render_template('case_custody.html', case=case, log=casedb.custody_log(case_id),
                           verify=casedb.verify_custody(case_id))


@bp.route('/cases/<case_id>/report.<fmt>')
def export(case_id, fmt):
    _case_or_404(case_id)
    ctx = report.build(case_id)
    stem = f'motoku-case-{case_id}'
    if fmt == 'json':
        body, mime = report.to_json(ctx), 'application/json'
    elif fmt == 'md':
        body, mime = report.to_markdown(ctx), 'text/markdown; charset=utf-8'
    elif fmt == 'zip':
        body, mime = report.to_csv_zip(ctx), 'application/zip'
    elif fmt in ('html', 'pdf'):
        html = render_template('case_report.html', r=ctx)
        if fmt == 'html':
            body, mime = html, 'text/html; charset=utf-8'
        else:
            try:
                body, mime = report.html_to_pdf(html), 'application/pdf'
            except RuntimeError as e:
                abort(503, description=str(e))
    else:
        abort(404)
    digest = report.digest(body)
    casedb.log_export(case_id, fmt, digest, current_actor())
    disposition = 'inline' if fmt == 'html' and request.args.get('view') else 'attachment'
    return Response(body, mimetype=mime, headers={
        'Content-Disposition': f'{disposition}; filename="{stem}.{fmt}"', 'X-Content-SHA256': digest})


@bp.route('/cases/<case_id>/watch', methods=['POST'])
def add_watch(case_id):
    _case_or_404(case_id)
    try:
        watch.add(request.form.get('type'), request.form.get('target'),
                  request.form.getlist('checks') or None, request.form.get('interval', 1440, type=int),
                  case_id, notify={'webhook': request.form.get('webhook') or None,
                                   'email': request.form.get('email') or None})
    except ValueError as e:
        flash(str(e))
    return redirect(url_for('cases.detail', case_id=case_id, tab='watch'))


