importScripts('common.js');

const MENUS = [
  { id: 'motoku-search-selection', title: 'Cari "%s" di Motoku', contexts: ['selection'] },
  { id: 'motoku-search-link', title: 'Cari tautan ini di Motoku', contexts: ['link'] },
  { id: 'motoku-image', title: 'Forensik gambar ini di Motoku', contexts: ['image'] },
  { id: 'motoku-page', title: 'Analisa domain halaman ini di Motoku', contexts: ['page'] },
];

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => MENUS.forEach(m => chrome.contextMenus.create(m)));
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const { server } = await settings();
  let url;
  switch (info.menuItemId) {
    case 'motoku-search-selection':
      url = `${server}/search?q=${encodeURIComponent(info.selectionText.trim())}`;
      break;
    case 'motoku-search-link':
      url = `${server}/search?q=${encodeURIComponent(info.linkUrl)}`;
      break;
    case 'motoku-image':
      url = `${server}/image?q=${encodeURIComponent(info.srcUrl)}&auto=1`;
      break;
    case 'motoku-page':
      url = `${server}/search?q=${encodeURIComponent(new URL(tab.url).hostname)}`;
      break;
  }
  if (url) chrome.tabs.create({ url, index: tab.index + 1 });
});
