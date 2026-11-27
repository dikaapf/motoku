// Shared helpers for the Motoku extension.
const DEFAULTS = { server: 'http://127.0.0.1:5000', token: '' };

async function settings() {
  const stored = await chrome.storage.sync.get(DEFAULTS);
  return { server: (stored.server || DEFAULTS.server).replace(/\/+$/, ''), token: stored.token || '' };
}

async function api(path, options = {}) {
  const { server, token } = await settings();
  if (!token) throw new Error('Token API belum diatur (buka Options).');
  const resp = await fetch(server + '/api/v1' + path, {
    ...options,
    headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', ...(options.headers || {}) },
  });
  const body = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(body.error || ('HTTP ' + resp.status));
  return body;
}
