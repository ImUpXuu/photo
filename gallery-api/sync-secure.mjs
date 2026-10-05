/**
 * 加密相册同步（服务端加密）
 *
 * 扫描来源目录里的相册（含 meta.json 且带 password 的才处理）：
 *   - 密码/盐存 data/<album>.json（gitignore，绝不外发）；盐首次生成后固定
 *   - 媒体用 AES-256-GCM 加密为 media/<album>/**.bin（iv12 + ct + tag16，同 build-photos 格式）
 *     密码变更时自动全量重加密
 *   - 生成 data/<album>.tree.json 目录树（含尺寸/日期，供前端解锁后拉取）
 *
 * 来源目录（都扫，后面的覆盖同名相册）：
 *   - $GALLERY_SRC_ROOT（默认 /root/gallery-src）：私有照片放这里，不入任何仓库
 *   - photo 仓库内的 gallery/ 目录（存在才扫）：走仓库自动更新流程
 *
 * 零依赖：node sync-secure.mjs
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, 'data');
const MEDIA_DIR = path.join(__dirname, 'media');

const SRC_ROOT = process.env.GALLERY_SRC_ROOT || '/root/gallery-src';
const REPO_GALLERY_DIR = process.env.GALLERY_REPO_DIR || path.join(__dirname, '..', 'gallery');

const IMAGE_EXT = /\.(jpg|jpeg|png|webp|gif|avif|tiff|tif)$/i;
const VIDEO_EXT = /\.(mp4|webm|mov|m4v|ogg)$/i;
const MEDIA_EXT = /\.(jpg|jpeg|png|webp|gif|avif|tiff|tif|mp4|webm|mov|m4v|ogg)$/i;
const ALBUM_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const PBKDF2_ITER = 100000;

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(MEDIA_DIR, { recursive: true });

function toPosix(p) {
  return p.split(path.sep).join('/');
}

function collectMediaFiles(dir, baseDir = dir) {
  const results = [];
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'meta.json' || entry.name.startsWith('.')) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) results.push(...collectMediaFiles(full, baseDir));
    else if (entry.isFile() && MEDIA_EXT.test(entry.name)) results.push(path.relative(baseDir, full));
  }
  return results;
}

function hasAnyMedia(dir) {
  return collectMediaFiles(dir).length > 0;
}

/** 从文件名猜拍摄日期（IMG_20240831_112531 这类），失败退回 mtime */
function mediaDate(filePath) {
  const m = path.basename(filePath).match(/(20\d{2})[._-]?(\d{2})[._-]?(\d{2})[._-]?(\d{2})(\d{2})/);
  if (m) {
    const t = Date.parse(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:00+08:00`);
    if (!Number.isNaN(t)) return new Date(t).toISOString();
  }
  return fs.statSync(filePath).mtime.toISOString();
}

// ---------- 尺寸嗅探（纯 Node，失败返回 null） ----------

function sniffSize(filePath, ext) {
  try {
    const fd = fs.openSync(filePath, 'r');
    const head = Buffer.alloc(Math.min(64 * 1024, fs.fstatSync(fd).size));
    fs.readSync(fd, head, 0, head.length, 0);
    fs.closeSync(fd);
    const e = ext.toLowerCase();
    if (e === '.png' && head.length >= 24 && head.toString('ascii', 12, 16) === 'IHDR') {
      return { width: head.readUInt32BE(16), height: head.readUInt32BE(20) };
    }
    if (e === '.gif' && head.length >= 10) {
      return { width: head.readUInt16LE(6), height: head.readUInt16LE(8) };
    }
    if (e === '.webp' && head.length >= 30 && head.toString('ascii', 0, 4) === 'RIFF' && head.toString('ascii', 8, 12) === 'WEBP') {
      const fourcc = head.toString('ascii', 12, 16);
      if (fourcc === 'VP8X') {
        return { width: head.readUIntLE(24, 3) + 1, height: head.readUIntLE(27, 3) + 1 };
      }
      if (fourcc === 'VP8 ') {
        // keyframe 起始码 9d 01 2a 后跟 14bit 宽、14bit 高
        if (head[23] === 0x9d && head[24] === 0x01 && head[25] === 0x2a) {
          return { width: head.readUInt16LE(26) & 0x3fff, height: head.readUInt16LE(28) & 0x3fff };
        }
      }
      if (fourcc === 'VP8L' && head[20] === 0x2f) {
        // 1 字节签名后：14bit 宽-1、14bit 高-1（LSB first）
        const v = head.readUInt32LE(21);
        return { width: (v & 0x3fff) + 1, height: ((v >>> 14) & 0x3fff) + 1 };
      }
    }
    if (e === '.jpg' || e === '.jpeg') {
      let off = 2;
      while (off + 9 < head.length) {
        if (head[off] !== 0xff) break;
        const marker = head[off + 1];
        if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
          off += 2;
          continue;
        }
        const len = head.readUInt16BE(off + 2);
        if ((marker >= 0xc0 && marker <= 0xcf) && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
          return { width: head.readUInt16BE(off + 7), height: head.readUInt16BE(off + 5) };
        }
        off += 2 + len;
      }
    }
  } catch {
    // ignore
  }
  return null;
}

// ---------- 加密 ----------

function encryptBuffer(plain, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
  return Buffer.concat([iv, enc, cipher.getAuthTag()]);
}

/** 元信息落盘：盐固定，密码变更时返回 true 要求全量重加密 */
function resolveAlbumMeta(album, albumSrcDir, existing) {
  const metaPath = path.join(albumSrcDir, 'meta.json');
  if (!fs.existsSync(metaPath)) return null;
  let meta;
  try {
    meta = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
  } catch (err) {
    console.error(`[skip] ${album}: meta.json 解析失败: ${err.message}`);
    return null;
  }
  const password = typeof meta.password === 'string' ? meta.password : '';
  if (!password) return null;

  let salt = existing?.salt;
  if (!salt || Buffer.from(salt, 'base64').length !== 16) {
    salt = crypto.randomBytes(16).toString('base64');
  }
  const rotated = Boolean(existing && existing.password && existing.password !== password);
  const record = {
    title: meta.title || album,
    description: meta.description || '',
    location: meta.location || '',
    characters: Array.isArray(meta.characters) ? meta.characters : [],
    date: meta.date || '',
    password,
    salt,
    passwordHash: crypto.createHash('sha256').update(password, 'utf8').digest('hex'),
  };
  fs.writeFileSync(path.join(DATA_DIR, `${album}.json`), JSON.stringify(record, null, 2));
  return { record, rotated };
}

function processAlbum(album, albumSrcDir) {
  if (!ALBUM_ID_RE.test(album)) {
    console.warn(`[skip] ${album}: 相册 ID 含不安全字符（仅允许字母数字_-），跳过`);
    return;
  }
  const metaFile = path.join(DATA_DIR, `${album}.json`);
  let existing = null;
  try {
    existing = JSON.parse(fs.readFileSync(metaFile, 'utf-8'));
  } catch {
    // first run
  }
  const resolved = resolveAlbumMeta(album, albumSrcDir, existing);
  if (!resolved) {
    console.log(`[skip] ${album}: meta.json 无 password，非加密相册`);
    return;
  }
  const { record, rotated } = resolved;
  if (rotated) console.log(`[${album}] 密码已变更，全量重加密`);

  const albumMediaDir = path.join(MEDIA_DIR, album);
  fs.mkdirSync(albumMediaDir, { recursive: true });

  const key = crypto.pbkdf2Sync(record.password, Buffer.from(record.salt, 'base64'), PBKDF2_ITER, 32, 'sha256');
  const files = collectMediaFiles(albumSrcDir);

  // 加密有变化的文件
  let encryptedCount = 0;
  for (const rel of files) {
    const srcPath = path.join(albumSrcDir, rel);
    const outRel = `${rel}.bin`;
    const outPath = path.join(albumMediaDir, outRel);
    const st = fs.statSync(srcPath);
    let stale = true;
    try {
      const outSt = fs.statSync(outPath);
      stale = rotated || st.mtimeMs > outSt.mtimeMs || st.size !== outSt.size;
    } catch {
      // new file
    }
    if (!stale) continue;
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, encryptBuffer(fs.readFileSync(srcPath), key));
    encryptedCount++;
    if (st.size > 8 * 1024 * 1024) console.log(`[${album}] encrypt ${(st.size / 1048576).toFixed(1)}MB ${toPosix(rel)}`);
  }

  // 清掉源里已删除的密文
  const validSet = new Set(files.map((rel) => `${toPosix(rel)}.bin`));
  let pruned = 0;
  const walkPrune = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walkPrune(full);
        if (fs.readdirSync(full).length === 0) fs.rmdirSync(full);
      } else if (entry.name.endsWith('.bin')) {
        const rel = toPosix(path.relative(albumMediaDir, full));
        if (!validSet.has(rel)) {
          fs.unlinkSync(full);
          pruned++;
        }
      }
    }
  };
  walkPrune(albumMediaDir);

  // 目录树
  const tree = buildTree(albumSrcDir, album, '');
  const payload = {
    title: record.title,
    description: record.description,
    location: record.location,
    characters: record.characters,
    date: record.date || latestDate(tree) || new Date().toISOString(),
    count: countMedia(tree),
    folders: tree.folders,
    photos: tree.photos,
  };
  fs.writeFileSync(path.join(DATA_DIR, `${album}.tree.json`), JSON.stringify(payload));
  console.log(
    `[${album}] ok: ${files.length} 个媒体（加密 ${encryptedCount}，清理 ${pruned}），树节点 ${countMedia(tree)}`
  );
}

function countMedia(node) {
  let n = node.photos.length;
  for (const f of node.folders) n += countMedia(f);
  return n;
}

function latestDate(node) {
  let d = 0;
  for (const p of node.photos) {
    const t = Date.parse(p.date);
    if (t > d) d = t;
  }
  for (const f of node.folders) {
    const t = Date.parse(latestDate(f) || 0);
    if (t > d) d = t;
  }
  return d ? new Date(d).toISOString() : '';
}

function firstCover(node) {
  const img = node.photos.find((p) => !p.isVideo);
  if (img) return img.url;
  const vid = node.photos.find((p) => p.isVideo);
  if (vid) return vid.poster || vid.url;
  for (const f of node.folders) {
    const c = firstCover(f);
    if (c) return c;
  }
  return '';
}

function buildTree(dir, album, relativeDir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const folders = [];
  const photos = [];

  const subdirs = entries
    .filter((e) => e.isDirectory() && !e.name.startsWith('.'))
    .sort((a, b) => a.name.localeCompare(b.name, 'zh-CN'));

  for (const entry of subdirs) {
    const childRel = relativeDir ? `${relativeDir}/${entry.name}` : entry.name;
    const childDir = path.join(dir, entry.name);
    if (!hasAnyMedia(childDir)) continue;
    const child = buildTree(childDir, album, childRel);
    folders.push({
      name: entry.name,
      path: childRel,
      cover: firstCover(child) || undefined,
      count: countMedia(child),
      folders: child.folders,
      photos: child.photos,
    });
  }

  const files = entries
    .filter((e) => e.isFile() && MEDIA_EXT.test(e.name) && e.name !== 'meta.json')
    .sort((a, b) => a.name.localeCompare(b.name, 'zh-CN'));

  for (const entry of files) {
    const relativePath = relativeDir ? `${relativeDir}/${entry.name}` : entry.name;
    const rawPath = path.join(dir, entry.name);
    const ext = path.extname(entry.name).toLowerCase();
    const isVideo = VIDEO_EXT.test(entry.name);
    const size = sniffSize(rawPath, ext);
    const url = `/media/${album}/${encodeURIComponent(relativePath)}.bin`;

    let poster;
    if (isVideo) {
      const base = entry.name.slice(0, -ext.length);
      for (const pe of ['.jpg', '.jpeg', '.png', '.webp']) {
        if (files.some((f) => f.name === base + pe)) {
          poster = `/media/${album}/${encodeURIComponent(path.join(relativeDir, base + pe))}.bin`;
          break;
        }
      }
    }

    photos.push({
      isVideo,
      url,
      filename: entry.name,
      date: mediaDate(rawPath),
      width: size?.width || (isVideo ? 1280 : 800),
      height: size?.height || (isVideo ? 720 : 600),
      poster,
    });
  }

  photos.sort((a, b) => Date.parse(b.date) - Date.parse(a.date));
  return { folders, photos };
}

// ---------- 入口 ----------

function main() {
  const sources = [];
  if (fs.existsSync(REPO_GALLERY_DIR)) sources.push(REPO_GALLERY_DIR);
  if (fs.existsSync(SRC_ROOT)) sources.push(SRC_ROOT);
  if (sources.length === 0) {
    console.log('[sync] 没有发现相册来源目录，跳过');
    return;
  }

  for (const root of sources) {
    for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
      const albumDir = path.join(root, entry.name);
      if (!fs.existsSync(path.join(albumDir, 'meta.json'))) {
        console.log(`[skip] ${entry.name}: 无 meta.json（密码相册必须带）`);
        continue;
      }
      processAlbum(entry.name, albumDir);
    }
  }
}

main();
