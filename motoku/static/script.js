document.addEventListener('DOMContentLoaded', function () {
    const myipEl = document.getElementById('myip');
    if (myipEl) {
        fetch('/api/myip')
            .then(r => r.json())
            .then(d => { myipEl.textContent = d.ip; })
            .catch(() => { myipEl.textContent = 'Gagal memuat'; });
    }

    initUnifiedSearch();
    initPrefillFromQuery();
    initCopyAndExport();
});

/* ── Unified search: live type hint ── */
function initUnifiedSearch() {
    document.querySelectorAll('[data-unified-search]').forEach(form => {
        const input = form.querySelector('input[name="q"]');
        const hint = form.querySelector('.detected-type');
        if (!input || !hint) return;
        let timer = null;
        input.addEventListener('input', () => {
            clearTimeout(timer);
            const q = input.value.trim();
            if (!q) { hint.textContent = ''; return; }
            timer = setTimeout(() => {
                fetch('/api/detect?q=' + encodeURIComponent(q))
                    .then(r => r.json())
                    .then(d => {
                        hint.textContent = d.type
                            ? 'Terdeteksi: ' + d.type_label + ' → ' + d.tools.map(t => t.label).join(', ')
                            : 'Tipe input tidak dikenali';
                    })
                    .catch(() => { hint.textContent = ''; });
            }, 250);
        });
    });
}

/* ── Tool pages: ?q=value prefills the form, &auto=1 submits it ── */
function initPrefillFromQuery() {
    const params = new URLSearchParams(window.location.search);
    const q = params.get('q');
    if (!q) return;
    const form = document.querySelector('form[method="POST"][data-tool-form], main form[method="POST"], .container form[method="POST"]');
    if (!form) return;
    const input = form.querySelector('input[type="text"], input[type="email"], input[type="url"], input[type="tel"], input[type="search"]');
    if (!input) return;
    input.value = q;
    if (params.get('auto') === '1') {
        // Remove the flag so a reload does not resubmit.
        params.delete('auto');
        const clean = window.location.pathname + (params.toString() ? '?' + params.toString() : '');
        window.history.replaceState(null, '', clean);
        const button = form.querySelector('button[type="submit"]');
        if (button) {
            button.disabled = true;
            button.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Memproses...';
        }
        form.submit();
    }
}

/* ── Copy & export ── */
function readResultData(id) {
    const el = document.getElementById(id || 'result-data');
    if (!el) return null;
    try { return JSON.parse(el.textContent); } catch (e) { return null; }
}

function getPath(obj, path) {
    if (!path) return obj;
    return path.split('.').reduce((acc, key) => (acc == null ? acc : acc[key]), obj);
}

function flatten(obj, prefix, out) {
    out = out || {};
    if (obj === null || typeof obj !== 'object') {
        out[prefix || 'value'] = obj;
        return out;
    }
    if (Array.isArray(obj)) {
        if (obj.every(v => v === null || typeof v !== 'object')) {
            out[prefix || 'value'] = obj.join('; ');
            return out;
        }
        obj.forEach((v, i) => flatten(v, prefix ? prefix + '.' + i : String(i), out));
        return out;
    }
    Object.keys(obj).forEach(k => flatten(obj[k], prefix ? prefix + '.' + k : k, out));
    return out;
}

function csvCell(value) {
    if (value === null || value === undefined) return '';
    const s = String(value);
    return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

function toCsv(data, rowsPath) {
    const rows = getPath(data, rowsPath);
    let records;
    if (Array.isArray(rows)) {
        records = rows.map(r => flatten(r));
    } else {
        const flat = flatten(data);
        records = Object.keys(flat).map(k => ({ field: k, value: flat[k] }));
    }
    const headers = [];
    records.forEach(r => Object.keys(r).forEach(k => { if (!headers.includes(k)) headers.push(k); }));
    const lines = [headers.map(csvCell).join(',')];
    records.forEach(r => lines.push(headers.map(h => csvCell(r[h])).join(',')));
    return lines.join('\r\n');
}

function download(content, filename, type) {
    const blob = new Blob([content], { type: type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
        return navigator.clipboard.writeText(text);
    }
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } finally { ta.remove(); }
    return Promise.resolve();
}

function flash(message) {
    let el = document.getElementById('motoku-toast');
    if (!el) {
        el = document.createElement('div');
        el.id = 'motoku-toast';
        el.className = 'toast-copy alert alert-success py-2 px-3 shadow';
        document.body.appendChild(el);
    }
    el.textContent = message;
    el.hidden = false;
    clearTimeout(el._timer);
    el._timer = setTimeout(() => { el.hidden = true; }, 1600);
}

function stamp() {
    return new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
}

function initCopyAndExport() {
    document.addEventListener('click', event => {
        const copyBtn = event.target.closest('.copy-btn[data-copy]');
        if (copyBtn) {
            copyText(copyBtn.dataset.copy).then(() => {
                copyBtn.classList.add('copied');
                flash('Disalin ke clipboard');
                setTimeout(() => copyBtn.classList.remove('copied'), 1200);
            });
            return;
        }

        const exportBtn = event.target.closest('[data-export]');
        if (!exportBtn) return;
        const data = readResultData(exportBtn.dataset.source);
        if (data === null) { flash('Tidak ada data untuk diekspor'); return; }
        const base = (exportBtn.dataset.filename || 'motoku') + '-' + stamp();
        const json = JSON.stringify(data, null, 2);

        switch (exportBtn.dataset.export) {
            case 'copy':
                copyText(json).then(() => flash('JSON disalin ke clipboard'));
                break;
            case 'json':
                download(json, base + '.json', 'application/json');
                break;
            case 'csv':
                download('﻿' + toCsv(data, exportBtn.dataset.rows), base + '.csv', 'text/csv;charset=utf-8');
                break;
        }
    });
}

/* ── Background jobs: live progress via Server-Sent Events ── */
document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.job-panel[data-events-url]').forEach(panel => {
        const bar = panel.querySelector('.job-bar');
        const status = panel.querySelector('.job-status');
        const message = panel.querySelector('.job-message');
        const logEl = panel.querySelector('.job-log');
        const label = panel.querySelector('.job-label');
        let reloaded = false;

        function render(job) {
            const pct = Math.max(0, Math.min(100, job.progress || 0));
            bar.style.width = pct + '%';
            bar.textContent = pct + '%';
            status.textContent = job.status;
            if (job.label) label.textContent = job.label;
            if (job.message) message.textContent = job.message;
            if (job.log && job.log.length) {
                logEl.textContent = job.log.slice(-15).join('\n');
                logEl.scrollTop = logEl.scrollHeight;
            }
        }

        function finish() {
            if (reloaded) return;
            reloaded = true;
            window.location.reload();
        }

        if (!window.EventSource) {
            const poll = () => fetch('/api/jobs/' + panel.dataset.jobId)
                .then(r => r.json())
                .then(job => {
                    render(job);
                    if (job.status === 'finished' || job.status === 'failed') finish();
                    else setTimeout(poll, 2000);
                });
            poll();
            return;
        }

        const source = new EventSource(panel.dataset.eventsUrl);
        source.onmessage = e => render(JSON.parse(e.data));
        source.addEventListener('done', e => {
            render(JSON.parse(e.data));
            source.close();
            setTimeout(finish, 400);
        });
        source.addEventListener('gone', () => source.close());
    });
});
