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
                        const t = window.MOTOKU ? window.MOTOKU.i18n : {};
                        hint.textContent = d.type
                            ? (t.detected || 'Terdeteksi') + ': ' + d.type_label + ' → ' + d.tools.map(x => x.label).join(', ')
                            : (t.unknownType || 'Tipe input tidak dikenali');
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
            button.innerHTML = '<span class="spinner-border spinner-border-sm"></span> ' + ((window.MOTOKU && MOTOKU.i18n.processing) || 'Memproses...');
        }
        form.submit();
    }
}

/* ── Copy & export ── */
function i18n(key, fallback) {
    return (window.MOTOKU && window.MOTOKU.i18n && window.MOTOKU.i18n[key]) || fallback;
}

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
                flash(i18n('copied', 'Disalin ke clipboard'));
                setTimeout(() => copyBtn.classList.remove('copied'), 1200);
            });
            return;
        }

        const exportBtn = event.target.closest('[data-export]');
        if (!exportBtn) return;
        const data = readResultData(exportBtn.dataset.source);
        if (data === null) { flash(i18n('noData', 'Tidak ada data untuk diekspor')); return; }
        const base = (exportBtn.dataset.filename || 'motoku') + '-' + stamp();
        const json = JSON.stringify(data, null, 2);

        switch (exportBtn.dataset.export) {
            case 'copy':
                copyText(json).then(() => flash(i18n('jsonCopied', 'JSON disalin ke clipboard')));
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


/* ── Save any tool result into a case ── */
document.addEventListener('DOMContentLoaded', function () {
    const modalEl = document.getElementById('save-case-modal');
    if (!modalEl || !window.bootstrap) return;
    const modal = new bootstrap.Modal(modalEl);
    const select = document.getElementById('save-case-select');
    const newBox = document.getElementById('save-case-new');
    const titleInput = document.getElementById('save-case-title-input');
    const status = document.getElementById('save-case-status');
    const csrf = () => document.querySelector('meta[name="csrf-token"]').content;
    let pending = null;

    select.addEventListener('change', () => { newBox.hidden = select.value !== '__new__'; });

    document.addEventListener('click', event => {
        const btn = event.target.closest('[data-save-case]');
        if (!btn) return;
        const source = document.getElementById(btn.dataset.saveCase);
        if (!source) return;
        pending = {tool: source.dataset.tool || 'generic', data: JSON.parse(source.textContent), label: btn.dataset.label || ''};
        status.textContent = '';
        titleInput.value = pending.label;
        fetch('/cases.json').then(r => r.json()).then(cases => {
            select.innerHTML = '';
            cases.forEach(c => select.add(new Option(c.title + ' (' + c.id + ')', c.id)));
            select.add(new Option('+ Buat case baru…', '__new__'));
            if (!cases.length) select.value = '__new__';
            newBox.hidden = select.value !== '__new__';
            modal.show();
        });
    });

    document.getElementById('save-case-submit').addEventListener('click', async () => {
        if (!pending) return;
        status.textContent = 'Menyimpan…';
        try {
            let caseId = select.value;
            if (caseId === '__new__') {
                const body = new URLSearchParams({title: titleInput.value || pending.label || 'Case baru', csrf_token: csrf()});
                const created = await fetch('/cases', {method: 'POST', body: body, redirect: 'follow'});
                caseId = created.url.split('/cases/')[1];
                if (!caseId) throw new Error('Gagal membuat case');
            }
            const resp = await fetch('/cases/' + caseId + '/import', {
                method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf()},
                body: JSON.stringify(pending),
            });
            const out = await resp.json();
            if (!resp.ok) throw new Error(out.error || resp.status);
            status.innerHTML = '';
            const link = document.createElement('a');
            link.href = out.url; link.className = 'text-success';
            link.textContent = `Tersimpan: ${out.entities_new} entity baru, ${out.relations} relasi, ${out.findings} temuan → buka case`;
            status.appendChild(link);
        } catch (e) {
            status.textContent = 'Gagal: ' + e.message;
        }
    });
});


/* ── Command palette (Ctrl/Cmd+K) and "/" to focus search ── */
document.addEventListener('DOMContentLoaded', function () {
    const modalEl = document.getElementById('palette-modal');
    if (!modalEl || !window.bootstrap || !window.MOTOKU) return;
    const modal = new bootstrap.Modal(modalEl);
    const input = document.getElementById('palette-input');
    const list = document.getElementById('palette-list');
    const T = window.MOTOKU.i18n;
    let cases = null, items = [], selected = 0;

    function score(text, query) {
        // Subsequence fuzzy match: lower is better; -1 = no match.
        text = text.toLowerCase();
        if (!query) return 0;
        const idx = text.indexOf(query);
        if (idx >= 0) return idx;
        let t = 0, gaps = 0;
        for (const ch of query) {
            const found = text.indexOf(ch, t);
            if (found < 0) return -1;
            gaps += found - t;
            t = found + 1;
        }
        return 100 + gaps;
    }

    function build(query) {
        const q = query.trim().toLowerCase();
        const out = [];
        if (q) out.push({label: T.searchFor.replace('{q}', query.trim()), icon: 'bi-search', color: 'success',
                         category: T.actions, url: '/search?q=' + encodeURIComponent(query.trim()), s: -1});
        window.MOTOKU.palette.forEach(t => {
            const s = score(t.label + ' ' + t.keywords + ' ' + t.category, q);
            if (s >= 0) out.push({...t, s});
        });
        (cases || []).forEach(c => {
            const s = score(c.title + ' ' + c.id, q);
            if (s >= 0) out.push({label: c.title, desc: c.id, icon: 'bi-folder2-open', color: 'success',
                                  category: T.cases, url: '/cases/' + c.id, s: s + 0.5});
        });
        if (!q || score(T.newCase, q) >= 0) out.push({label: T.newCase, icon: 'bi-folder-plus', color: 'success',
                                                       category: T.actions, url: '/cases', s: 50});
        return out.sort((a, b) => a.s - b.s).slice(0, 40);
    }

    function render() {
        items = build(input.value);
        selected = Math.min(selected, Math.max(0, items.length - 1));
        list.innerHTML = '';
        if (!items.length) {
            list.innerHTML = '<div class="text-secondary p-3">' + T.noMatch + '</div>';
            return;
        }
        items.forEach((it, i) => {
            const a = document.createElement('a');
            a.href = it.url;
            a.className = 'list-group-item list-group-item-action bg-transparent d-flex gap-2 align-items-center' + (i === selected ? ' active' : '');
            a.setAttribute('role', 'option');
            a.setAttribute('aria-selected', i === selected ? 'true' : 'false');
            const icon = document.createElement('i');
            icon.className = 'bi ' + it.icon + ' text-' + it.color + ' fs-5';
            const body = document.createElement('div');
            body.className = 'flex-grow-1 text-truncate';
            const title = document.createElement('div');
            title.textContent = it.label;
            body.appendChild(title);
            if (it.desc) {
                const d = document.createElement('small');
                d.className = 'text-secondary';
                d.textContent = it.desc;
                body.appendChild(d);
            }
            const cat = document.createElement('small');
            cat.className = 'badge bg-dark border border-secondary';
            cat.textContent = it.category;
            a.append(icon, body, cat);
            list.appendChild(a);
        });
        const active = list.querySelector('.active');
        if (active) active.scrollIntoView({block: 'nearest'});
    }

    function open() {
        input.value = '';
        selected = 0;
        render();
        modal.show();
        if (cases === null) {
            cases = [];
            fetch('/cases.json').then(r => r.ok ? r.json() : []).then(c => { cases = c; render(); }).catch(() => {});
        }
    }

    modalEl.addEventListener('shown.bs.modal', () => input.focus());
    input.addEventListener('input', () => { selected = 0; render(); });
    input.addEventListener('keydown', e => {
        if (e.key === 'ArrowDown') { selected = Math.min(selected + 1, items.length - 1); render(); e.preventDefault(); }
        else if (e.key === 'ArrowUp') { selected = Math.max(selected - 1, 0); render(); e.preventDefault(); }
        else if (e.key === 'Enter' && items[selected]) { window.location.href = items[selected].url; e.preventDefault(); }
    });
    document.querySelectorAll('[data-palette-open]').forEach(el => el.addEventListener('click', e => { e.preventDefault(); open(); }));
    document.addEventListener('keydown', e => {
        const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName) || document.activeElement.isContentEditable;
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); open(); }
        else if (e.key === '/' && !typing) {
            const search = document.getElementById('nav-search-input');
            if (search) { e.preventDefault(); search.focus(); }
        }
    });
});
