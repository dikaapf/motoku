(async () => {
  const s = await settings();
  document.getElementById('server').value = s.server;
  document.getElementById('token').value = s.token;
})();

document.getElementById('save').addEventListener('click', async () => {
  const server = document.getElementById('server').value.trim().replace(/\/+$/, '');
  const token = document.getElementById('token').value.trim();
  const status = document.getElementById('status');
  try {
    const origin = new URL(server).origin + '/*';
    const granted = await chrome.permissions.request({ origins: [origin] });
    if (!granted) { status.textContent = 'Izin akses ke server ditolak.'; return; }
  } catch (e) { status.textContent = 'URL server tidak valid.'; return; }
  await chrome.storage.sync.set({ server, token });
  try {
    const me = await api('/me');
    status.textContent = `Terhubung sebagai token "${me.name}" (scope: ${me.scopes.join(', ')})`;
  } catch (e) { status.textContent = 'Tersimpan, tetapi koneksi gagal: ' + e.message; }
});
