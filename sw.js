/* Floor Fix hosted shell. Offline first. Same origin only. Silent.
   Serves the lock screen and encrypted packs from the core cache.
   Serves unlocked library files from the on-device plain cache only. */
const VERSION = '234fa7b26ac9-r4';
const CORE = 'ffh-core-' + VERSION;
const PLAIN = 'ffh-plain-' + VERSION;
const SHELL = [
  './',
  './index.html',
  './lock.js',
  './lock.css',
  './sw.js',
  './manifest.webmanifest',
  './robots.txt',
  './crypto.json',
  './icons/apple-touch-icon.png',
  './icons/favicon-48.png',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/icon-maskable-512.png'
];
const BUNDLES = ["./b/c00.bin", "./b/c01.bin"];

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CORE);
    const files = SHELL.concat(BUNDLES);
    await cache.addAll(files.map((u) => new Request(u, { cache: 'reload' })));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    const stale = keys.filter((k) => {
      if (k === CORE || k === PLAIN) return false;
      return k.indexOf('ffh-core-') === 0 || k.indexOf('ffh-plain-') === 0;
    });
    await Promise.all(stale.map((k) => caches.delete(k)));
    await self.clients.claim();
    // Only force a reload when this phone still had an older pack cached.
    // A first-time install must not bounce the lock screen.
    if (stale.length) {
      const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      await Promise.all(windows.map(async (c) => {
        try { c.postMessage({ type: 'ffh-reload', version: VERSION }); } catch (e) { /* old clients may ignore */ }
        if (c.navigate) {
          try { await c.navigate(c.url); } catch (e) { /* some browsers refuse navigate */ }
        }
      }));
    }
  })());
});

self.addEventListener('message', (event) => {
  if (!event.data) return;
  if (event.data === 'ffh-skip-waiting') self.skipWaiting();
  if (event.data === 'ffh-claim') self.clients.claim();
  if (event.data === 'ffh-version' && event.source) {
    event.source.postMessage({ type: 'ffh-version', version: VERSION, files: SHELL.length + BUNDLES.length });
  }
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  event.respondWith((async () => {
    const plain = await caches.open(PLAIN);
    let hit = await plain.match(req, { ignoreSearch: true });
    if (hit) return hit;
    const core = await caches.open(CORE);
    hit = await core.match(req, { ignoreSearch: true });
    if (hit) return hit;
    if (req.mode === 'navigate') {
      hit = await core.match('./index.html') || await core.match('index.html');
      if (hit) return hit;
    }
    try {
      return await fetch(req);
    } catch (err) {
      return new Response('', { status: 504, statusText: 'Offline and not saved on this device' });
    }
  })());
});
