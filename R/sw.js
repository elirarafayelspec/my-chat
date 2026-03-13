self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

// 收到后台推送时显示通知
self.addEventListener('push', e => {
    let data = { title: '🤍', body: '你有新消息' };
    try { data = e.data.json(); } catch(_) {}
    e.waitUntil(
        self.registration.showNotification(data.title, {
            body: data.body,
            tag: 'chat-msg',
            renotify: true,
            silent: false
        })
    );
});

self.addEventListener('notificationclick', e => {
    e.notification.close();
    e.waitUntil(
        self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(cs => {
            for (let c of cs) { if ('focus' in c) return c.focus(); }
            if (self.clients.openWindow) return self.clients.openWindow('./');
        })
    );
});