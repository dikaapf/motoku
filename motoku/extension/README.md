# Motoku OSINT — browser extension

Manifest V3 extension for Chrome, Edge, Brave (and Firefox 128+).

1. Open `chrome://extensions`, enable **Developer mode**, click **Load unpacked**
   and choose this folder.
2. Open the extension **Options**, set the server URL (e.g. `http://127.0.0.1:5000`)
   and an API token created at `/settings/tokens` (scopes `read`, `write`, `scan`).
   The browser will ask permission to reach that server only.

Features: right-click selected text / a link / an image / the page to open it in
Motoku; popup search; add the current page to a case; quick reputation check of
the current site (optionally saved to the selected case).
