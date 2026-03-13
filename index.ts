// ——— 类型定义 ———
interface Env {
  PUSH_STORE: KVNamespace;
  VAPID_PUBLIC_KEY: string;
  VAPID_PRIVATE_KEY: string;
}

interface PushSubscription {
  endpoint: string;
  keys: { p256dh: string; auth: string };
}

interface ScheduledEvents {
  nextHourlyAt: number;      // 下次自动消息时间（ms timestamp）
  pendingLetterAt: number;   // 待发来信时间（ms timestamp，0=无）
  nextVideoAt: number;       // 下次视频来电时间（ms timestamp）
  hourlyInterval: number;    // 消息间隔（分钟）
  partnerName: string;       // 对方昵称
  autoReplyEnabled: boolean;
  partnerVideoEnabled: boolean;
}

// ——— VAPID JWT 生成 ———
async function buildVapidJwt(audience: string, privateKeyB64: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'ES256', typ: 'JWT' };
  const payload = { aud: audience, exp: now + 3600, sub: 'mailto:admin@example.com' };
  const enc = (obj: object) => btoa(JSON.stringify(obj)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const signingInput = `${enc(header)}.${enc(payload)}`;

  const rawKey = Uint8Array.from(atob(privateKeyB64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    'pkcs8', rawKey.buffer,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, ['sign']
  );
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    new TextEncoder().encode(signingInput)
  );
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${signingInput}.${sigB64}`;
}

// ——— Web Push 加密 ———
async function encryptPayload(subscription: PushSubscription, plaintext: string): Promise<{ ciphertext: Uint8Array; salt: Uint8Array; serverPublicKey: Uint8Array }> {
  const clientPublicKey = Uint8Array.from(atob(subscription.keys.p256dh.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  const clientAuthSecret = Uint8Array.from(atob(subscription.keys.auth.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

  const serverKeyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const serverPublicKeyRaw = new Uint8Array(await crypto.subtle.exportKey('raw', serverKeyPair.publicKey));

  const clientKey = await crypto.subtle.importKey('raw', clientPublicKey, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: clientKey }, serverKeyPair.privateKey as CryptoKey, 256));

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hkdfKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);

  const prk = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: clientAuthSecret, info: new TextEncoder().encode('Content-Encoding: auth\0') },
    hkdfKey, 256
  ));
  const prkKey = await crypto.subtle.importKey('raw', prk, 'HKDF', false, ['deriveBits']);

  const keyInfo = concat(new TextEncoder().encode('Content-Encoding: aesgcm\0'), new Uint8Array([0x00, serverPublicKeyRaw.length]), serverPublicKeyRaw, new Uint8Array([0x00, clientPublicKey.length]), clientPublicKey);
  const nonceInfo = concat(new TextEncoder().encode('Content-Encoding: nonce\0'), new Uint8Array([0x00, serverPublicKeyRaw.length]), serverPublicKeyRaw, new Uint8Array([0x00, clientPublicKey.length]), clientPublicKey);

  const contentKey = new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: keyInfo }, prkKey, 128));
  const nonce = new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: nonceInfo }, prkKey, 96));

  const aesKey = await crypto.subtle.importKey('raw', contentKey, 'AES-GCM', false, ['encrypt']);
  const data = new TextEncoder().encode(plaintext);
  const padded = concat(new Uint8Array(2), data);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, padded));

  return { ciphertext: encrypted, salt, serverPublicKey: serverPublicKeyRaw };
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) { out.set(a, offset); offset += a.length; }
  return out;
}

// ——— 发送 Web Push ———
async function sendWebPush(subscription: PushSubscription, title: string, body: string, env: Env): Promise<boolean> {
  try {
    const url = new URL(subscription.endpoint);
    const audience = `${url.protocol}//${url.host}`;
    const jwt = await buildVapidJwt(audience, env.VAPID_PRIVATE_KEY);
    const { ciphertext, salt, serverPublicKey } = await encryptPayload(subscription, JSON.stringify({ title, body, icon: '/apple-touch-icon.png' }));

    const resp = await fetch(subscription.endpoint, {
      method: 'POST',
      headers: {
        'Authorization': `vapid t=${jwt},k=${env.VAPID_PUBLIC_KEY}`,
        'Content-Type': 'application/octet-stream',
        'Content-Encoding': 'aesgcm',
        'Encryption': `salt=${btoa(String.fromCharCode(...salt)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')}`,
        'Crypto-Key': `dh=${btoa(String.fromCharCode(...serverPublicKey)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')}`,
        'TTL': '86400',
      },
      body: ciphertext,
    });
    return resp.ok || resp.status === 201;
  } catch (e) {
    console.error('sendWebPush error:', e);
    return false;
  }
}

// ——— Cron：每30分钟自动检查并推送 ———
async function handleScheduled(env: Env): Promise<void> {
  const subJson = await env.PUSH_STORE.get('subscription');
  if (!subJson) return;

  const subscription: PushSubscription = JSON.parse(subJson);
  const eventsJson = await env.PUSH_STORE.get('scheduled_events');
  if (!eventsJson) return;

  const events: ScheduledEvents = JSON.parse(eventsJson);
  const now = Date.now();
  let updated = false;

  // 检查：自动消息
  if (events.autoReplyEnabled && events.nextHourlyAt > 0 && now >= events.nextHourlyAt) {
    await sendWebPush(subscription, events.partnerName || '对方', '发来了消息', env);
    // 安排下一次
    const intervalMs = (events.hourlyInterval || 60) * 60 * 1000;
    events.nextHourlyAt = now + intervalMs;
    updated = true;
  }

  // 检查：待发来信
  if (events.pendingLetterAt > 0 && now >= events.pendingLetterAt) {
    await sendWebPush(subscription, '新来信', `${events.partnerName || '对方'}给你写了一封信`, env);
    events.pendingLetterAt = 0;
    updated = true;
  }

  // 检查：视频来电
  if (events.partnerVideoEnabled && events.nextVideoAt > 0 && now >= events.nextVideoAt) {
    await sendWebPush(subscription, `${events.partnerName || '对方'}邀请您进行视频通话`, '', env);
    // 随机1~6小时后再来一次
    events.nextVideoAt = now + (1 + Math.random() * 5) * 60 * 60 * 1000;
    updated = true;
  }

  if (updated) {
    await env.PUSH_STORE.put('scheduled_events', JSON.stringify(events));
  }
}

// ——— HTTP 请求处理 ———
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });

    // GET /ping
    if (url.pathname === '/ping') {
      return new Response(JSON.stringify({ ok: true }), { headers: { ...cors, 'Content-Type': 'application/json' } });
    }

    // POST /subscribe — 保存推送订阅
    if (url.pathname === '/subscribe' && request.method === 'POST') {
      const body = await request.json() as any;
      // 兼容直接发 sub 或包了一层 {subscription: sub} 两种格式
      const subscription = body.endpoint ? body : body.subscription;
      await env.PUSH_STORE.put('subscription', JSON.stringify(subscription));
      return new Response(JSON.stringify({ ok: true }), { headers: { ...cors, 'Content-Type': 'application/json' } });
    }

    // POST /schedule — 网页同步计划事件到 Worker
    if (url.pathname === '/schedule' && request.method === 'POST') {
      const events = await request.json() as ScheduledEvents;
      await env.PUSH_STORE.put('scheduled_events', JSON.stringify(events));
      return new Response(JSON.stringify({ ok: true }), { headers: { ...cors, 'Content-Type': 'application/json' } });
    }

    // POST /notify — 立即发送一条通知
    if (url.pathname === '/notify' && request.method === 'POST') {
      const subJson = await env.PUSH_STORE.get('subscription');
      if (!subJson) return new Response(JSON.stringify({ ok: false, error: 'no subscription' }), { status: 404, headers: cors });
      const subscription: PushSubscription = JSON.parse(subJson);
      const { title, body } = await request.json() as { title: string; body: string };
      const ok = await sendWebPush(subscription, title, body, env);
      return new Response(JSON.stringify({ ok }), { headers: { ...cors, 'Content-Type': 'application/json' } });
    }

    return new Response('Not found', { status: 404, headers: cors });
  },

  // Cron 触发器（每30分钟）
  async scheduled(_event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    await handleScheduled(env);
  },
};
