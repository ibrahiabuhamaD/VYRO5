import { createServer } from 'node:http';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, open, readFile, stat, unlink } from 'node:fs/promises';
import { extname, isAbsolute, relative, resolve, sep } from 'node:path';
import { randomBytes, randomUUID, scrypt as scryptCallback, createHash, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';
import { db } from './server/db.js';

const root = fileURLToPath(new URL('.', import.meta.url));
const uploadDirectory = resolve(root, process.env.VYRO_UPLOAD_DIR || 'server/uploads');
await mkdir(uploadDirectory, { recursive: true });
const port = Number(process.env.PORT || 4173);
const host = process.env.HOST || (process.env.NODE_ENV === 'production' ? '0.0.0.0' : '127.0.0.1');
const sessionLifetime = 7 * 24 * 60 * 60 * 1000;
const maxVideoBytes = 50 * 1024 * 1024;
const scrypt = promisify(scryptCallback);
const mimeTypes = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8', '.svg': 'image/svg+xml',
  '.mp4': 'video/mp4', '.webm': 'video/webm',
};

function json(response, status, body, headers = {}) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  response.end(JSON.stringify(body));
}

function fail(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

async function readJson(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 1024 * 1024) throw fail(413, 'Request body is too large.');
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw fail(400, 'Invalid JSON request.'); }
}

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

function cookieValue(request, name) {
  const pair = (request.headers.cookie || '').split(';').map((part) => part.trim()).find((part) => part.startsWith(`${name}=`));
  return pair ? pair.slice(name.length + 1) : null;
}

function sessionCookie(token, maxAge) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `vyro_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}`;
}

function userRecord(userId) {
  return db.prepare(`
    SELECT u.id, u.name, u.username, u.email, u.age, u.gender, u.role, u.created_at,
      (SELECT COUNT(*) FROM follows WHERE followed_id = u.id) AS followersCount,
      (SELECT COUNT(*) FROM follows WHERE follower_id = u.id) AS followingCount,
      (SELECT COUNT(*) FROM videos WHERE user_id = u.id) AS videoCount,
      (SELECT COUNT(*) FROM likes JOIN videos ON videos.id = likes.video_id WHERE videos.user_id = u.id) AS likesCount
    FROM users u WHERE u.id = ?
  `).get(userId) || null;
}

function currentUser(request) {
  const token = cookieValue(request, 'vyro_session');
  if (!token) return null;
  const session = db.prepare('SELECT user_id, expires_at FROM sessions WHERE token_hash = ?').get(hashToken(token));
  if (!session) return null;
  if (session.expires_at <= Date.now()) {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(token));
    return null;
  }
  return userRecord(session.user_id);
}

function requireUser(user) {
  if (!user) throw fail(401, 'Sign in to continue.');
  return user;
}

function serializeVideo(row, viewerId) {
  return {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    username: row.username,
    avatarUrl: null,
    caption: row.caption,
    sound: row.sound,
    visibility: row.visibility,
    src: `/media/${row.storage_name}`,
    createdAt: row.created_at,
    likes: row.likesCount,
    comments: row.commentsCount,
    isLiked: Boolean(row.isLiked),
    isFollowing: Boolean(row.isFollowing),
    isOwner: row.user_id === viewerId,
  };
}

const videoSelect = `
  SELECT v.*, u.name, u.username,
    (SELECT COUNT(*) FROM likes WHERE video_id = v.id) AS likesCount,
    (SELECT COUNT(*) FROM comments WHERE video_id = v.id) AS commentsCount,
    EXISTS(SELECT 1 FROM likes WHERE video_id = v.id AND user_id = ?) AS isLiked,
    EXISTS(SELECT 1 FROM follows WHERE followed_id = v.user_id AND follower_id = ?) AS isFollowing
  FROM videos v JOIN users u ON u.id = v.user_id
`;

function videoById(videoId, viewerId = 0) {
  return db.prepare(`${videoSelect} WHERE v.id = ?`).get(viewerId, viewerId, videoId) || null;
}

function createSession(userId, response) {
  const token = randomBytes(32).toString('hex');
  const expiresAt = Date.now() + sessionLifetime;
  db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(hashToken(token), userId, expiresAt);
  response.setHeader('Set-Cookie', sessionCookie(token, sessionLifetime / 1000));
}

async function register(request, response) {
  const body = await readJson(request);
  const name = String(body.name || '').trim().slice(0, 80);
  const username = String(body.username || '').trim().toLowerCase();
  const email = String(body.email || '').trim().toLowerCase();
  const age = Number(body.age);
  const gender = ['male', 'female', 'other', 'unspecified'].includes(body.gender) ? body.gender : 'unspecified';
  const password = String(body.password || '');
  if (name.length < 2 || !/^[a-z0-9_.]{3,24}$/.test(username)) throw fail(400, 'Enter a name and a username (3-24 letters, numbers, dots, or underscores).');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw fail(400, 'Enter a valid email address.');
  if (!Number.isInteger(age) || age < 13 || age > 120) throw fail(400, 'You must be at least 13 years old.');
  if (password.length < 12 || password.length > 128) throw fail(400, 'Password must be between 12 and 128 characters.');
  if (db.prepare('SELECT 1 FROM users WHERE email = ? OR username = ?').get(email, username)) throw fail(409, 'That email or username is already registered.');
  const salt = randomBytes(16).toString('hex');
  const passwordHash = (await scrypt(password, salt, 64)).toString('hex');
  const result = db.prepare('INSERT INTO users (name, username, email, age, gender, password_salt, password_hash) VALUES (?, ?, ?, ?, ?, ?, ?)').run(name, username, email, age, gender, salt, passwordHash);
  createSession(Number(result.lastInsertRowid), response);
  json(response, 201, { user: userRecord(Number(result.lastInsertRowid)) });
}

async function login(request, response) {
  const body = await readJson(request);
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  const user = db.prepare('SELECT id, password_salt, password_hash FROM users WHERE email = ?').get(email);
  if (!user || password.length > 128) throw fail(401, 'Email or password is incorrect.');
  const candidate = await scrypt(password, user.password_salt, 64);
  const stored = Buffer.from(user.password_hash, 'hex');
  if (stored.length !== candidate.length || !timingSafeEqual(stored, candidate)) throw fail(401, 'Email or password is incorrect.');
  createSession(user.id, response);
  json(response, 200, { user: userRecord(user.id) });
}

async function uploadVideo(request, response, user) {
  const mimeType = request.headers['content-type'] || '';
  const extensions = { 'video/mp4': '.mp4', 'video/webm': '.webm' };
  const extension = extensions[mimeType.toLowerCase()];
  if (!extension) throw fail(415, 'Upload an MP4 or WebM video.');
  if (Number(request.headers['content-length'] || 0) > maxVideoBytes) throw fail(413, 'Video must be 50 MB or smaller.');
  const caption = decodeURIComponent(String(request.headers['x-video-caption'] || '')).trim().slice(0, 220);
  const sound = decodeURIComponent(String(request.headers['x-video-sound'] || 'Original sound')).trim().slice(0, 120) || 'Original sound';
  const visibilityValue = request.headers['x-video-visibility'];
  const visibility = ['public', 'followers', 'private'].includes(visibilityValue) ? visibilityValue : 'public';
  const id = randomUUID();
  const storageName = `${id}${extension}`;
  const path = resolve(uploadDirectory, storageName);
  let size = 0;
  try {
    await pipeline(request, new Transform({
      transform(chunk, encoding, callback) {
        size += chunk.length;
        callback(size > maxVideoBytes ? fail(413, 'Video must be 50 MB or smaller.') : null, chunk);
      },
    }), createWriteStream(path, { flags: 'wx' }));
    if (size === 0) throw fail(400, 'Choose a video before publishing.');
    const fileHandle = await open(path, 'r');
    try {
      const header = Buffer.alloc(12);
      const { bytesRead } = await fileHandle.read(header, 0, header.length, 0);
      const validMp4 = mimeType === 'video/mp4' && bytesRead >= 8 && header.toString('ascii', 4, 8) === 'ftyp';
      const validWebm = mimeType === 'video/webm' && bytesRead >= 4 && header.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]));
      if (!validMp4 && !validWebm) throw fail(415, 'The selected file is not a valid MP4 or WebM video.');
    } finally { await fileHandle.close(); }
    db.prepare('INSERT INTO videos (id, user_id, storage_name, mime_type, caption, sound, visibility) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, user.id, storageName, mimeType, caption, sound, visibility);
  } catch (error) {
    await unlink(path).catch(() => {});
    throw error;
  }
  json(response, 201, { video: serializeVideo(videoById(id, user.id), user.id) });
}

async function handleApi(request, response, url, user) {
  const path = url.pathname;
  if (path === '/api/health' && request.method === 'GET') {
    db.prepare('SELECT 1').get();
    return json(response, 200, { status: 'ok' });
  }
  if (path === '/api/auth/register' && request.method === 'POST') return register(request, response);
  if (path === '/api/auth/login' && request.method === 'POST') return login(request, response);
  if (path === '/api/auth/logout' && request.method === 'POST') {
    const token = cookieValue(request, 'vyro_session');
    if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(token));
    response.writeHead(200, { 'Set-Cookie': sessionCookie('', 0), 'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8' });
    response.end(JSON.stringify({ ok: true })); return;
  }
  if (path === '/api/me' && request.method === 'GET') return json(response, 200, { user });
  if (path === '/api/feed' && request.method === 'GET') {
    const type = url.searchParams.get('type') || 'foryou';
    if (type === 'following' && !user) throw fail(401, 'Sign in to view your following feed.');
    const viewerId = user?.id || 0;
    const where = type === 'following'
      ? `WHERE (v.user_id = ? OR (v.visibility = 'public' AND v.user_id IN (SELECT followed_id FROM follows WHERE follower_id = ?)) OR (v.visibility = 'followers' AND v.user_id IN (SELECT followed_id FROM follows WHERE follower_id = ?)))`
      : `WHERE v.visibility = 'public'`;
    const params = type === 'following' ? [viewerId, viewerId, viewerId, viewerId, viewerId] : [viewerId, viewerId];
    const rows = db.prepare(`${videoSelect} ${where} ORDER BY v.created_at DESC LIMIT 60`).all(...params);
    return json(response, 200, { videos: rows.map((row) => serializeVideo(row, viewerId)) });
  }
  if (path === '/api/videos' && request.method === 'POST') return uploadVideo(request, response, requireUser(user));
  const videoMatch = path.match(/^\/api\/videos\/([0-9a-f-]+)(?:\/(like|comments))?$/i);
  if (videoMatch) {
    const [, videoId, operation] = videoMatch;
    const viewerId = user?.id || 0;
    const video = videoById(videoId, viewerId);
    const followsOwner = video && viewerId ? db.prepare('SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?').get(viewerId, video.user_id) : false;
    if (!video || (video.visibility === 'private' && video.user_id !== viewerId) || (video.visibility === 'followers' && video.user_id !== viewerId && !followsOwner)) throw fail(404, 'Video not found.');
    if (operation === 'like' && request.method === 'POST') {
      const viewer = requireUser(user);
      const existing = db.prepare('SELECT 1 FROM likes WHERE user_id = ? AND video_id = ?').get(viewer.id, videoId);
      if (existing) db.prepare('DELETE FROM likes WHERE user_id = ? AND video_id = ?').run(viewer.id, videoId);
      else db.prepare('INSERT INTO likes (user_id, video_id) VALUES (?, ?)').run(viewer.id, videoId);
      return json(response, 200, { isLiked: !existing, likes: db.prepare('SELECT COUNT(*) AS count FROM likes WHERE video_id = ?').get(videoId).count });
    }
    if (operation === 'comments' && request.method === 'GET') {
      const comments = db.prepare(`SELECT c.id, c.body, c.created_at AS createdAt, u.id AS userId, u.name, u.username
        FROM comments c JOIN users u ON u.id = c.user_id WHERE c.video_id = ? ORDER BY c.created_at DESC LIMIT 100`).all(videoId);
      return json(response, 200, { comments });
    }
    if (operation === 'comments' && request.method === 'POST') {
      const viewer = requireUser(user);
      const body = await readJson(request);
      const text = String(body.body || '').trim();
      if (text.length < 1 || text.length > 1000) throw fail(400, 'Comment must be between 1 and 1000 characters.');
      const result = db.prepare('INSERT INTO comments (user_id, video_id, body) VALUES (?, ?, ?)').run(viewer.id, videoId, text);
      const comment = db.prepare('SELECT c.id, c.body, c.created_at AS createdAt, u.id AS userId, u.name, u.username FROM comments c JOIN users u ON u.id = c.user_id WHERE c.id = ?').get(result.lastInsertRowid);
      return json(response, 201, { comment });
    }
    if (!operation && request.method === 'DELETE') {
      const viewer = requireUser(user);
      if (video.user_id !== viewer.id && viewer.role !== 'admin') throw fail(403, 'You cannot delete this video.');
      db.prepare('DELETE FROM videos WHERE id = ?').run(videoId);
      await unlink(resolve(uploadDirectory, video.storage_name)).catch(() => {});
      return json(response, 200, { ok: true });
    }
  }
  const followMatch = path.match(/^\/api\/users\/(\d+)\/follow$/);
  if (followMatch && ['POST', 'DELETE'].includes(request.method)) {
    const viewer = requireUser(user);
    const followedId = Number(followMatch[1]);
    if (followedId === viewer.id) throw fail(400, 'You cannot follow yourself.');
    if (!db.prepare('SELECT 1 FROM users WHERE id = ?').get(followedId)) throw fail(404, 'User not found.');
    if (request.method === 'POST') db.prepare('INSERT OR IGNORE INTO follows (follower_id, followed_id) VALUES (?, ?)').run(viewer.id, followedId);
    else db.prepare('DELETE FROM follows WHERE follower_id = ? AND followed_id = ?').run(viewer.id, followedId);
    return json(response, 200, { following: request.method === 'POST', followersCount: db.prepare('SELECT COUNT(*) AS count FROM follows WHERE followed_id = ?').get(followedId).count });
  }
  if (path === '/api/search' && request.method === 'GET') {
    const query = url.searchParams.get('q')?.trim().slice(0, 80) || '';
    if (!query) return json(response, 200, { users: [], videos: [] });
    const likeQuery = `%${query.replace(/[\\%_]/g, '\\$&')}%`;
    const users = db.prepare(`SELECT u.id, u.name, u.username,
      (SELECT COUNT(*) FROM follows WHERE followed_id = u.id) AS followersCount,
      EXISTS(SELECT 1 FROM follows WHERE followed_id = u.id AND follower_id = ?) AS isFollowing
      FROM users u WHERE u.name LIKE ? ESCAPE '\\' OR u.username LIKE ? ESCAPE '\\' ORDER BY followersCount DESC LIMIT 20`).all(user?.id || 0, likeQuery, likeQuery);
    const rows = db.prepare(`${videoSelect} WHERE v.visibility = 'public' AND v.caption LIKE ? ESCAPE '\\' ORDER BY v.created_at DESC LIMIT 30`).all(user?.id || 0, user?.id || 0, likeQuery);
    return json(response, 200, { users, videos: rows.map((row) => serializeVideo(row, user?.id || 0)) });
  }
  const profileMatch = path.match(/^\/api\/users\/([a-z0-9_.]+)$/i);
  if (profileMatch && request.method === 'GET') {
    const profile = db.prepare('SELECT id, name, username, created_at AS createdAt FROM users WHERE username = ?').get(profileMatch[1]);
    if (!profile) throw fail(404, 'User not found.');
    const profileUser = userRecord(profile.id);
    const canSeeFollowers = user?.id === profile.id || db.prepare('SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?').get(user?.id || 0, profile.id);
    const viewerId = user?.id || 0;
    const rows = db.prepare(`${videoSelect} WHERE v.user_id = ? AND (v.visibility = 'public' OR (v.visibility = 'followers' AND ?) OR (v.visibility = 'private' AND ?)) ORDER BY v.created_at DESC LIMIT 60`).all(viewerId, viewerId, profile.id, Number(Boolean(canSeeFollowers)), Number(user?.id === profile.id));
    const publicProfile = {
      id: profileUser.id,
      name: profileUser.name,
      username: profileUser.username,
      followersCount: profileUser.followersCount,
      followingCount: profileUser.followingCount,
      videoCount: profileUser.videoCount,
      likesCount: profileUser.likesCount,
    };
    return json(response, 200, { user: publicProfile, videos: rows.map((row) => serializeVideo(row, viewerId)) });
  }
  json(response, 404, { message: 'API route not found.' });
}

const server = createServer(async (request, response) => {
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('X-Frame-Options', 'DENY');
  response.setHeader('Referrer-Policy', 'same-origin');
  const url = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`);
  if (url.pathname.startsWith('/api/')) {
    try {
      if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method) && request.headers.origin && new URL(request.headers.origin).host !== request.headers.host) throw fail(403, 'Cross-origin requests are not allowed.');
      await handleApi(request, response, url, currentUser(request));
    } catch (error) {
      if (!response.headersSent) json(response, error.status || 500, { message: error.status ? error.message : 'The server could not complete that request.' });
      if (!error.status) console.error(error);
    }
    return;
  }
  if (url.pathname.startsWith('/media/')) {
    const filename = url.pathname.slice('/media/'.length);
    if (!/^[0-9a-f-]{36}\.(mp4|webm)$/i.test(filename)) { response.writeHead(404); response.end('Not found'); return; }
    try {
      const filePath = resolve(uploadDirectory, filename);
      const media = db.prepare('SELECT id, user_id, visibility FROM videos WHERE storage_name = ?').get(filename);
      if (!media) throw new Error('Missing media');
      const viewer = currentUser(request);
      const owner = viewer?.id === media.user_id;
      const follower = viewer && db.prepare('SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?').get(viewer.id, media.user_id);
      if (media.visibility === 'private' && !owner || media.visibility === 'followers' && !owner && !follower) { response.writeHead(404); response.end('Not found'); return; }
      const fileInfo = await stat(filePath);
      const range = request.headers.range?.match(/^bytes=(\d*)-(\d*)$/);
      let start = 0; let end = fileInfo.size - 1; let status = 200;
      if (range) {
        start = range[1] ? Number(range[1]) : Math.max(0, fileInfo.size - Number(range[2]));
        end = range[2] && range[1] ? Number(range[2]) : end;
        if (start > end || start >= fileInfo.size) { response.writeHead(416, { 'Content-Range': `bytes */${fileInfo.size}` }); response.end(); return; }
        status = 206;
      }
      response.writeHead(status, {
        'Content-Type': mimeTypes[extname(filename)],
        'Content-Length': end - start + 1,
        'Cache-Control': 'private, no-store',
        'Accept-Ranges': 'bytes',
        ...(range ? { 'Content-Range': `bytes ${start}-${end}/${fileInfo.size}` } : {}),
      });
      createReadStream(filePath, { start, end }).pipe(response);
    } catch { response.writeHead(404); response.end('Not found'); }
    return;
  }
  const requestedPath = url.pathname === '/' ? '/index.html' : decodeURIComponent(url.pathname);
  const filePath = resolve(root, `.${requestedPath}`);
  const relativePath = relative(root, filePath);
  if (relativePath === '..' || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) {
    response.writeHead(403); response.end('Forbidden'); return;
  }
  try {
    if (!(await stat(filePath)).isFile()) throw new Error('Not a file');
    const content = await readFile(filePath);
    response.writeHead(200, { 'Content-Type': mimeTypes[extname(filePath)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    response.end(content);
  } catch {
    response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    response.end('Not found');
  }
});

server.listen(port, host, () => console.log(`VYRO running at http://${host}:${port}`));
