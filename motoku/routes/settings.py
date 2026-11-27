from flask import Blueprint, redirect, render_template, request, url_for

from services import api_tokens

bp = Blueprint('settings', __name__)


@bp.route('/settings/tokens', methods=['GET', 'POST'])
def tokens():
    new_token = error = None
    if request.method == 'POST':
        try:
            new_token = api_tokens.create(request.form.get('name'), request.form.getlist('scopes'))
        except ValueError as e:
            error = str(e)
    return render_template('tokens.html', tokens=api_tokens.list_tokens(), new_token=new_token, error=error,
                           scopes=api_tokens.SCOPES)


@bp.route('/settings/tokens/<int:token_id>/revoke', methods=['POST'])
def revoke(token_id):
    api_tokens.revoke(token_id)
    return redirect(url_for('settings.tokens'))
