from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for

from services import casedb, jobs, watch

bp = Blueprint('watch', __name__)


@bp.route('/watchlist', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        try:
            watch.add(request.form.get('type'), request.form.get('target'),
                      request.form.getlist('checks') or None, request.form.get('interval', 1440, type=int),
                      request.form.get('case_id') or None, request.form.get('label') or None,
                      notify={'webhook': request.form.get('webhook') or None,
                              'email': request.form.get('email') or None,
                              'min_severity': request.form.get('min_severity') or None})
        except ValueError as e:
            flash(str(e))
        return redirect(url_for('watch.index'))
    return render_template('watchlist.html', items=watch.list_all(), alerts=watch.list_alerts(100),
                           types=watch.TARGET_TYPES, defaults=watch.DEFAULT_CHECKS,
                           cases=casedb.list_cases('open'))


@bp.route('/watchlist/<int:watch_id>/run', methods=['POST'])
def run_now(watch_id):
    item = watch.get(watch_id)
    if item is None:
        return jsonify({'error': 'not found'}), 404
    job_id = jobs.enqueue('watch', f'{item["type"]}:{item["target"]}', {'watch_id': watch_id})
    return redirect(url_for('job_list') + f'#{job_id}')


@bp.route('/watchlist/<int:watch_id>/toggle', methods=['POST'])
def toggle(watch_id):
    item = watch.get(watch_id)
    if item:
        watch.set_enabled(watch_id, not item['enabled'])
    return redirect(url_for('watch.index'))


@bp.route('/watchlist/<int:watch_id>/delete', methods=['POST'])
def delete(watch_id):
    watch.delete(watch_id)
    return redirect(url_for('watch.index'))


@bp.route('/alerts/<int:alert_id>/ack', methods=['POST'])
def ack(alert_id):
    watch.acknowledge(alert_id)
    return redirect(request.referrer or url_for('watch.index'))
