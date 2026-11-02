// Intentionally insecure teaching demo. Binds to 127.0.0.1, uses fake data only. Never deploy.
import http from 'node:http'; import crypto from 'node:crypto'; import fs from 'node:fs'; import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
const signingKey = 'demo-signing-key-not-real';
const db = new DatabaseSync(':memory:');
db.exec('create table members(id integer primary key,email text,phone text,pw text)');
for (let i = 1; i <= 1000; i++) db.prepare('insert into members values(?,?,?,?)').run(i, `member${i}@example.invalid`, `000-0000-${String(i).padStart(4, '0')}`, crypto.createHash('md5').update('pass' + i).digest('hex'));
const partner = { db };
fs.mkdirSync('public/uploads', { recursive: true });
const verify = t => { try { const [a, b, s] = t.split('.'); if (crypto.createHmac('sha256', signingKey).update(a + '.' + b).digest('base64url') !== s) return null; return JSON.parse(Buffer.from(b, 'base64url')); } catch { return null; } };
const send = (r, c, o) => { r.writeHead(c, { 'content-type': 'application/json' }); r.end(JSON.stringify(o)); };
http.createServer(async (q, r) => {
  const u = new URL(q.url, 'http://x'); const me = verify((q.headers.authorization || '').replace('Bearer ', ''));
  if (u.pathname === '/api/profile') { if (!me) return send(r, 401, {}); return send(r, 200, db.prepare('select id,email,phone from members where id=?').get(me.sub) || { sub: me.sub }); }
  if (u.pathname === '/api/orders') { if (!me) return send(r, 401, {}); return send(r, 200, db.prepare('select id,email from members where id=?').get(+u.searchParams.get('memberId')) || {}); }
  if (u.pathname === '/upload' && q.method === 'POST') { const buf = []; for await (const c of q) buf.push(c); fs.writeFileSync(path.join('public/uploads', u.searchParams.get('name')), Buffer.concat(buf)); return send(r, 200, {}); }
  if (u.pathname.startsWith('/uploads/')) { const m = await import(path.resolve('public/uploads', path.basename(u.pathname))); return send(r, 200, { result: m.default(partner) }); }
  send(r, 404, {});
}).listen(18090, '127.0.0.1');
