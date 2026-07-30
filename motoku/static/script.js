document.addEventListener('DOMContentLoaded', function () {
    const myipEl = document.getElementById('myip');
    if (myipEl) {
        fetch('/api/myip')
            .then(r => r.json())
            .then(d => { myipEl.textContent = d.ip; })
            .catch(() => { myipEl.textContent = 'Gagal memuat'; });
    }
});
