/**
 * 加密相册 API（Kaleido secure gallery）
 *
 * 零依赖 Node 服务：
 *   POST /api/albums/:id/unlock  校验密码（来自元信息），限流按 IP，成功后签发 HttpOnly cookie
 *   GET  /api/albums/:id/tree    需要 cookie，返回相册目录树（媒体为相对 URL）
 *   GET  /media/:album/<path>    需要 cookie，读取 .bin 密文并服务端解密后输出
 *   GET  /healthz                健康检查
 *
 * 数据文件（由 sync-secure.mjs 生成，均在 gitignore 内）：
 *   data/<album>.json       相册元信息：passwordHash / password / salt（绝不外发）
 *   data/<album>.tree.json  相册目录树
 *   media/<album>/**.bin    AES-256-GCM 密文（iv(12) + ciphertext + tag(16)，与前端 build-photos 同格式）
 */
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3691);
const HOST = process.env.HOST || '127.0.0.1';
const SECRET = process.env.SECRET;
const DATA_DIR = path.join(__dirname, 'data');
const MEDIA_DIR = path.join(__dirname, 'media');
const COOKIE_NAME_PREFIX = 'gsecure_';
const COOKIE_MAX_AGE = Number(process.env.COOKIE_MAX_AGE || 7 * 24 * 3600);
const COOKIE_SAMESITE = process.env.COOKIE_SAMESITE || 'Lax'; // Lax: 同站(upxuu.com 子域)可用；跨站部署可设 None
const RATE_WINDOW_MS = Number(process.env.RATE_WINDOW_MS || 15 * 60 * 1000);
const RATE_MAX_FAILS = Number(process.env.RATE_MAX_FAILS || 5);
const CORS_ORIGINS = (
  process.env.CORS_ORIGINS ||
  'https://life.upxuu.com,https://upxuu.com,http://localhost:3000,http://127.0.0.1:3000'
)
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

if (!SECRET) {
  console.error('[fatal] SECRET is required (put it in gallery-api/.env)');
  process.exit(1);
}

const MIME = {
  '.webp': 'image/webp',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.gif': 'image/gif',
  '.avif': 'image/avif',
  '.tif': 'image/tiff',
  '.tiff': 'image/tiff',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.mov': 'video/quicktime',
  '.m4v': 'video/x-m4v',
  '.ogg': 'video/ogg',
};

const ALBUM_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

// ---------- 小工具 ----------

function json(res, code, obj, extraHeaders = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(body);
}

function allowedOrigin(origin) {
  return origin && CORS_ORIGINS.includes(origin) ? origin : null;
}

function applyCors(req, res) {
  const origin = allowedOrigin(req.headers.origin);
  if (!origin) return false;
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Vary', 'Origin');
  return true;
}

function clientIp(req) {
  // 仅由本机 Caddy 反代进入，取 X-Forwarded-For 第一个 IP
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) {
    return xff.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function timingSafeEqualStr(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// ---------- 限流（按 IP，内存滑动窗口） ----------

const rateMap = new Map(); // ip -> { fails: number[], blockedUntil: number }

function rateCheck(ip) {
  const now = Date.now();
  let entry = rateMap.get(ip);
  if (!entry) {
    entry = { fails: [], blockedUntil: 0 };
    rateMap.set(ip, entry);
  }
  if (entry.blockedUntil > now) {
    return { blocked: true, retryAfter: Math.ceil((entry.blockedUntil - now) / 1000) };
  }
  entry.fails = entry.fails.filter((t) => now - t < RATE_WINDOW_MS);
  return { blocked: false };
}

function rateRecordFail(ip) {
  const now = Date.now();
  const entry = rateMap.get(ip) || { fails: [], blockedUntil: 0 };
  entry.fails.push(now);
  if (entry.fails.length >= RATE_MAX_FAILS) {
    entry.blockedUntil = now + RATE_WINDOW_MS;
    entry.fails = [];
  }
  rateMap.set(ip, entry);
}

function rateClear(ip) {
  rateMap.delete(ip);
}

// ---------- cookie 签发 / 校验 ----------

function cookieName(album) {
  return COOKIE_NAME_PREFIX + album;
}

function signPayload(album, exp) {
  return crypto.createHmac('sha256', SECRET).update(`${album}.${exp}`).digest('hex');
}

function issueCookie(res, album) {
  const exp = Math.floor(Date.now() / 1000) + COOKIE_MAX_AGE;
  const sig = signPayload(album, exp);
  const parts = [
    `${cookieName(album)}=${exp}.${sig}`,
    'Path=/',
    'HttpOnly',
    `Max-Age=${COOKIE_MAX_AGE}`,
    `SameSite=${COOKIE_SAMESITE}`,
  ];
  // SameSite=None 必须带 Secure 才会被浏览器接受
  if (COOKIE_SAMESITE.toLowerCase() === 'none') parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function checkAuth(req, album) {
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return false;
  const name = cookieName(album);
  let token = null;
  for (const pair of cookieHeader.split(';')) {
    const idx = pair.indexOf('=');
    if (idx === -1) continue;
    if (pair.slice(0, idx).trim() === name) {
      token = pair.slice(idx + 1).trim();
      break;
    }
  }
  if (!token) return false;
  const dot = token.indexOf('.');
  if (dot === -1) return false;
  const expStr = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (!/^\d+$/.test(expStr)) return false;
  const exp = Number(expStr);
  if (exp * 1000 < Date.now()) return false;
  return timingSafeEqualStr(sig, signPayload(album, exp));
}

// ---------- 元信息（密码从元信息取） ----------

function readAlbumMeta(album) {
  const file = path.join(DATA_DIR, `${album}.json`);
  try {
    const meta = JSON.parse(fs.readFileSync(file, 'utf-8'));
    if (!meta.passwordHash || !meta.password || !meta.salt) return null;
    return meta;
  } catch {
    return null;
  }
}

// ---------- 解密 ----------

function decryptBin(packed, meta) {
  if (packed.length < 12 + 16) throw new Error('invalid payload');
  const salt = Buffer.from(meta.salt, 'base64');
  const key = crypto.pbkdf2Sync(meta.password, salt, 100000, 32, 'sha256');
  const iv = packed.subarray(0, 12);
  const tag = packed.subarray(packed.length - 16);
  const data = packed.subarray(12, packed.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

// ---------- 处理器 ----------

function handleUnlock(req, res, album, body) {
  const ip = clientIp(req);
  const rate = rateCheck(ip);
  if (rate.blocked) {
    json(res, 429, { error: 'rate_limited' }, { 'Retry-After': String(rate.retryAfter) });
    return;
  }

  let password = '';
  try {
    const parsed = JSON.parse(body || '{}');
    if (typeof parsed.password === 'string') password = parsed.password;
  } catch {
    // fallthrough
  }

  const meta = readAlbumMeta(album);
  if (!meta) {
    json(res, 404, { error: 'not_found' });
    return;
  }

  if (!password || !timingSafeEqualStr(sha256Hex(password), meta.passwordHash)) {
    rateRecordFail(ip);
    json(res, 401, { error: 'bad_password' });
    return;
  }

  rateClear(ip);
  issueCookie(res, album);
  console.log(`[unlock] album=${album} ok=true`);
  json(res, 200, { ok: true });
}

function handleTree(res, album) {
  const file = path.join(DATA_DIR, `${album}.tree.json`);
  try {
    const tree = fs.readFileSync(file);
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': tree.length,
      // 内容会随照片更新，浏览器可短暂缓存但需重新验证
      'Cache-Control': 'private, no-cache',
    });
    res.end(tree);
  } catch {
    json(res, 404, { error: 'not_found' });
  }
}

function handleMedia(req, res, album, rel) {
  const albumDir = path.join(MEDIA_DIR, album);
  const filePath = path.resolve(albumDir, rel);
  if (filePath !== albumDir && !filePath.startsWith(albumDir + path.sep)) {
    json(res, 400, { error: 'bad_path' });
    return;
  }
  if (!filePath.endsWith('.bin')) {
    json(res, 400, { error: 'bad_path' });
    return;
  }

  const meta = readAlbumMeta(album);
  if (!meta) {
    json(res, 404, { error: 'not_found' });
    return;
  }

  let packed;
  try {
    packed = fs.readFileSync(filePath);
  } catch {
    json(res, 404, { error: 'not_found' });
    return;
  }

  let plain;
  try {
    plain = decryptBin(packed, meta);
  } catch (err) {
    console.error(`[media] decrypt failed album=${album} path=${rel}: ${err.message}`);
    json(res, 500, { error: 'decrypt_failed' });
    return;
  }

  const baseName = path.basename(filePath).replace(/\.bin$/, '');
  const contentType = MIME[path.extname(baseName)] || 'application/octet-stream';

  const baseHeaders = {
    'Content-Type': contentType,
    // 明文只允许浏览器私有缓存，绝不能进共享/CDN 缓存
    'Cache-Control': 'private, max-age=86400',
    'Accept-Ranges': 'bytes',
    'X-Content-Type-Options': 'nosniff',
  };

  // 单段 Range（视频拖动进度条用）
  const rangeHeader = req.headers.range;
  const rangeMatch =
    typeof rangeHeader === 'string' ? rangeHeader.match(/^bytes=(\d*)-(\d*)$/) : null;
  if (rangeMatch && (rangeMatch[1] !== '' || rangeMatch[2] !== '')) {
    let start;
    let end;
    if (rangeMatch[1] === '') {
      const suffix = Number(rangeMatch[2]);
      start = Math.max(0, plain.length - suffix);
      end = plain.length - 1;
    } else {
      start = Number(rangeMatch[1]);
      end = rangeMatch[2] === '' ? plain.length - 1 : Math.min(Number(rangeMatch[2]), plain.length - 1);
    }
    if (Number.isNaN(start) || Number.isNaN(end) || start > end || start >= plain.length) {
      res.writeHead(416, { 'Content-Range': `bytes */${plain.length}` });
      res.end();
      return;
    }
    const chunk = plain.subarray(start, end + 1);
    res.writeHead(206, {
      ...baseHeaders,
      'Content-Range': `bytes ${start}-${end}/${plain.length}`,
      'Content-Length': chunk.length,
    });
    res.end(chunk);
    return;
  }

  res.writeHead(200, { ...baseHeaders, 'Content-Length': plain.length });
  res.end(plain);
}

// ---------- HTTP 服务 ----------

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = decodeURIComponent(url.pathname);

  // CORS（仅对配置过的来源；预检直接 204）
  if (req.headers.origin) {
    if (req.method === 'OPTIONS') {
      if (applyCors(req, res)) {
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        res.setHeader('Access-Control-Max-Age', '600');
        res.writeHead(204);
        res.end();
      } else {
        res.writeHead(204);
        res.end();
      }
      return;
    }
    applyCors(req, res);
  }

  if (pathname === '/healthz' && req.method === 'GET') {
    json(res, 200, { ok: true, uptime: process.uptime() });
    return;
  }

  const unlockMatch = pathname.match(/^\/api\/albums\/([^/]+)\/unlock$/);
  if (unlockMatch && req.method === 'POST') {
    const album = unlockMatch[1];
    if (!ALBUM_ID_RE.test(album)) {
      json(res, 400, { error: 'bad_album' });
      return;
    }
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 8192) {
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => handleUnlock(req, res, album, Buffer.concat(chunks).toString('utf8')));
    req.on('error', () => {});
    return;
  }

  const treeMatch = pathname.match(/^\/api\/albums\/([^/]+)\/tree$/);
  if (treeMatch && req.method === 'GET') {
    const album = treeMatch[1];
    if (!ALBUM_ID_RE.test(album)) {
      json(res, 400, { error: 'bad_album' });
      return;
    }
    if (!checkAuth(req, album)) {
      json(res, 401, { error: 'unauthorized' });
      return;
    }
    handleTree(res, album);
    return;
  }

  const mediaMatch = pathname.match(/^\/media\/([^/]+)\/(.+)$/);
  if (mediaMatch && (req.method === 'GET' || req.method === 'HEAD')) {
    const album = mediaMatch[1];
    const rel = mediaMatch[2];
    if (!ALBUM_ID_RE.test(album)) {
      json(res, 400, { error: 'bad_album' });
      return;
    }
    if (!checkAuth(req, album)) {
      json(res, 401, { error: 'unauthorized' });
      return;
    }
    if (req.method === 'HEAD') {
      res.writeHead(200, { 'Content-Length': 0 });
      res.end();
      return;
    }
    handleMedia(req, res, album, rel);
    return;
  }

  json(res, 404, { error: 'not_found' });
});

// 限流表定期清理，防止长期运行下缓慢膨胀
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateMap) {
    if (entry.blockedUntil < now && entry.fails.every((t) => now - t > RATE_WINDOW_MS)) {
      rateMap.delete(ip);
    }
  }
}, 10 * 60 * 1000).unref();

server.listen(PORT, HOST, () => {
  console.log(`[gallery-api] listening on ${HOST}:${PORT} origins=${CORS_ORIGINS.length}`);
});
