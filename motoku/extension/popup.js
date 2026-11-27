const status = document.getElementById('status');
const say = (msg) => { status.textContent = msg; };
let activeTab = null;

(async () => {
  [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  try { document.getElementById('page-host').textContent = new URL(activeTab.url).hostname; } catch (e) { /* chrome:// pages */ }
  const select = document.getElementById('case-select');
  try {
    const cases = await api('/cases?status=open');
    select.innerHTML = '';
    cases.forEach(c => select.add(new Option(`${c.title} (${c.id})`, c.id)));
    if (!cases.length) select.add(new Option('Belum ada case terbuka', ''));
  } catch (e) {
    select.innerHTML = '';
    select.add(new Option('Tidak terhubung: ' + e.message, ''));
  }
})();

document.getElementById('search-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const q = document.getElementById('q').value.trim();
  if (!q) return;
  const { server } = await settings();
  chrome.tabs.create({ url: `${server}/search?q=${encodeURIComponent(q)}` });
});

document.getElementById('add-page').addEventListener('click', async () => {
  const caseId = document.getElementById('case-select').value;
  if (!caseId) return say('Pilih case terlebih dahulu.');
  try {
    const url = activeTab.url;
    await api(`/cases/${caseId}/entities`, { method: 'POST', body: JSON.stringify({ type: 'url', value: url, label: activeTab.title }) });
    await api(`/cases/${caseId}/entities`, { method: 'POST', body: JSON.stringify({ type: 'domain', value: new URL(url).hostname }) });
    say('Ditambahkan ke case ' + caseId);
  } catch (e) { say('Gagal: ' + e.message); }
});

document.getElementById('run-intel').addEventListener('click', async () => {
  say('Memeriksa…');
  try {
    const host = new URL(activeTab.url).hostname;
    const caseId = document.getElementById('case-select').value || undefined;
    const r = await api('/tools/intel', { method: 'POST', body: JSON.stringify({ value: host, case_id: caseId }) });
    const s = r.result.summary;
    say(`${host}: ${s.verdict} (${s.malicious} berbahaya, ${s.suspicious} mencurigakan, ${s.sources_ok} sumber)` + (caseId ? ' · disimpan ke case' : ''));
  } catch (e) { say('Gagal: ' + e.message); }
});

document.getElementById('open-options').addEventListener('click', (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); });
