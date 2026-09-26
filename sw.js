const CACHE_NAME = 'vyro-shell-v9';
const scopeUrl = new URL(self.registration.scope);
const SHELL_FILES = ['', 'styles.css', 'manifest.webmanifest', 'assets/vyro-icon.svg', 'src/app.js', 'src/api.js', 'src/db.js']
  .map((path) => new URL(path, scopeUrl).href);
const apiPath = new URL('api/', scopeUrl).pathname;
const mediaPath = new URL('media/', scopeUrl).pathname;

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES)));
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key)))));
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin || url.pathname.startsWith(apiPath) || url.pathname.startsWith(mediaPath)) return;
  event.respondWith(caches.match(event.request).then((cached) => cached || fetch(event.request).then((response) => {
    if (response.ok) caches.open(CACHE_NAME).then((cache) => cache.put(event.request, response.clone()));
    return response;
  })));
});
