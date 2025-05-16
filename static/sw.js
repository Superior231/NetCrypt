const cacheName = 'netcrypt-cache-v1';

const filesToCache = [
    '/',
    '/static/css/auth.css',
    '/static/css/style.css',
    '/static/js/auth.js',
    '/static/js/script.js',
    '/static/img/globe.png',
    '/static/img/globe2.png',
    '/static/img/globe3.png',
    '/static/img/id.png',
    '/static/img/sg.png',
    '/static/img/us.png',
    'https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css',
    'https://unpkg.com/boxicons@2.1.4/css/boxicons.min.css',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css',
    'https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js',
];

self.addEventListener("install", function (event) {
    event.waitUntil(
        caches.open(cacheName).then(function (cache) {
            return cache.addAll(filesToCache);
        })
    );
});

self.addEventListener("activate", function (event) {
    event.waitUntil(
        caches.keys().then(function (keyList) {
            return Promise.all(
                keyList.map(function (key) {
                    if (key !== cacheName) {
                        return caches.delete(key);
                    }
                })
            );
        })
    );
});

self.addEventListener("fetch", function (event) {
    if (event.request.method !== "GET") return;

    event.respondWith(
        fetch(event.request)
            .then(function (response) {
                return response;
            })
            .catch(function () {
                return caches.match(event.request);
            })
    );
});

