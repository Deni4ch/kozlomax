const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || 'dqfqgbsyq',
  api_key: process.env.CLOUDINARY_API_KEY || '923275628596982',
  api_secret: process.env.CLOUDINARY_API_SECRET || '1Nxcg7j_j-VupLKFtS-JmEZ896s'
});

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.static('public'));
app.use(express.json({ limit: '10mb' }));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 15 * 1024 * 1024 } });
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function uploadStream(buffer, options) {
  return new Promise((resolve, reject) => {
    cloudinary.uploader.upload_stream(options, (err, result) => {
      if (err) reject(err); else resolve(result);
    }).end(buffer);
  });
}

async function initDB() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
    username TEXT UNIQUE, name TEXT, surname TEXT, age INTEGER,
    bio TEXT, avatar_url TEXT, status_mode TEXT DEFAULT 'auto',
    last_seen TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);
  for (const [col, type] of [['name','TEXT'],['surname','TEXT'],['age','INTEGER'],['username','TEXT'],
    ['status_mode','TEXT'],['bio','TEXT'],['avatar_url','TEXT'],['last_seen','TIMESTAMP']]) {
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS ${col} ${type}`).catch(()=>{});
  }
  await pool.query(`CREATE TABLE IF NOT EXISTS contacts (
    id SERIAL PRIMARY KEY, owner_email TEXT NOT NULL, contact_email TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(owner_email, contact_email)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY, room TEXT NOT NULL, email TEXT NOT NULL, name TEXT,
    text TEXT, type TEXT DEFAULT 'text', file_url TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);
  for (const [col, type] of [['room','TEXT'],['name','TEXT'],['type','TEXT'],['file_url','TEXT']]) {
    await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS ${col} ${type}`).catch(()=>{});
  }
  // Fix: remove NOT NULL constraint on text (for images/audio messages)
  await pool.query(`ALTER TABLE messages ALTER COLUMN text DROP NOT NULL`).catch(()=>{});
  await pool.query(`CREATE TABLE IF NOT EXISTS blocks (
    id SERIAL PRIMARY KEY, blocker_email TEXT NOT NULL, blocked_email TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(blocker_email, blocked_email)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS mutes (
    id SERIAL PRIMARY KEY, owner_email TEXT NOT NULL, room TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(owner_email, room)
  )`);
  console.log('БД готова');
}
initDB().catch(console.error);

const JWT_SECRET = process.env.JWT_SECRET || 'kozlomax-super-secret-2026';
const onlineUsers = new Map();

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Нет токена' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Сессия истекла' }); }
}
function computeVisibleStatus(email, statusMode) {
  const isOnline = onlineUsers.has(email) && onlineUsers.get(email).sockets.size > 0;
  if (statusMode === 'invisible') return false;
  if (statusMode === 'dnd') return isOnline ? 'dnd' : false;
  return isOnline;
}
function broadcastStatus(email, statusMode) {
  io.emit('user status', { email, online: computeVisibleStatus(email, statusMode) });
}
function getOtherEmail(room, myEmail) {
  if (!room.startsWith('dm_')) return null;
  return room.slice(3).split('___').find(e => e !== myEmail) || null;
}

// AUTH
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Заполни все поля' });
  if (password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Неверный формат почты' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, hashed]);
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, email });
  } catch { res.status(400).json({ error: 'Такая почта уже существует' }); }
});

app.post('/api/update-profile', async (req, res) => {
  const { token, name, surname, age, username, status_mode, bio } = req.body;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (username) {
      if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
        return res.status(400).json({ error: 'Username: 3-20 символов, буквы/цифры/_' });
      const ex = await pool.query('SELECT email FROM users WHERE username=$1 AND email!=$2', [username, decoded.email]);
      if (ex.rows.length) return res.status(400).json({ error: 'Username уже занят' });
    }
    await pool.query(
      'UPDATE users SET name=$1,surname=$2,age=$3,username=$4,status_mode=COALESCE($5,status_mode),bio=$6 WHERE email=$7',
      [name, surname||null, age||null, username||null, status_mode||null, bio||null, decoded.email]
    );
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  const user = r.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: 'Неверная почта или пароль' });
  const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, email: user.email, name: user.name||user.email, username: user.username, status_mode: user.status_mode||'auto' });
});

app.get('/api/me', authMiddleware, async (req, res) => {
  const r = await pool.query('SELECT email,name,username,status_mode,bio,avatar_url FROM users WHERE email=$1', [req.user.email]);
  res.json(r.rows[0]);
});

// USERS
app.get('/api/search', authMiddleware, async (req, res) => {
  const q = (req.query.q||'').trim().replace(/^@/,'');
  if (q.length < 2) return res.json([]);
  const r = await pool.query(
    `SELECT email,name,username,avatar_url FROM users WHERE (username ILIKE $1 OR name ILIKE $1) AND email!=$2 LIMIT 10`,
    [`%${q}%`, req.user.email]
  );
  res.json(r.rows);
});

app.get('/api/profile/:email', authMiddleware, async (req, res) => {
  const r = await pool.query(
    'SELECT email,name,username,bio,avatar_url,last_seen,status_mode FROM users WHERE email=$1',
    [req.params.email]
  );
  if (!r.rows.length) return res.status(404).json({ error: 'Не найден' });
  const u = r.rows[0];
  u.online = computeVisibleStatus(u.email, u.status_mode);
  res.json(u);
});

app.get('/api/contacts', authMiddleware, async (req, res) => {
  const r = await pool.query(
    `SELECT u.email,u.name,u.username,u.avatar_url,u.status_mode FROM contacts c
     JOIN users u ON u.email=c.contact_email WHERE c.owner_email=$1 ORDER BY u.name`,
    [req.user.email]
  );
  res.json(r.rows.map(u => ({ ...u, online: computeVisibleStatus(u.email, u.status_mode) })));
});

app.post('/api/contacts/add', authMiddleware, async (req, res) => {
  const { contactEmail } = req.body;
  if (!contactEmail || contactEmail === req.user.email) return res.status(400).json({ error: 'Неверный email' });
  const check = await pool.query('SELECT email FROM users WHERE email=$1', [contactEmail]);
  if (!check.rows.length) return res.status(404).json({ error: 'Пользователь не найден' });
  await pool.query('INSERT INTO contacts(owner_email,contact_email) VALUES($1,$2) ON CONFLICT DO NOTHING', [req.user.email, contactEmail]);
  await pool.query('INSERT INTO contacts(owner_email,contact_email) VALUES($1,$2) ON CONFLICT DO NOTHING', [contactEmail, req.user.email]);
  const myInfo = await pool.query('SELECT email,name,username,avatar_url FROM users WHERE email=$1', [req.user.email]);
  io.to(`user:${contactEmail}`).emit('new contact', myInfo.rows[0]);
  res.json({ success: true });
});

// BLOCKS
app.post('/api/block', authMiddleware, async (req, res) => {
  await pool.query('INSERT INTO blocks(blocker_email,blocked_email) VALUES($1,$2) ON CONFLICT DO NOTHING', [req.user.email, req.body.targetEmail]);
  res.json({ success: true });
});
app.post('/api/unblock', authMiddleware, async (req, res) => {
  await pool.query('DELETE FROM blocks WHERE blocker_email=$1 AND blocked_email=$2', [req.user.email, req.body.targetEmail]);
  res.json({ success: true });
});
app.get('/api/blocks', authMiddleware, async (req, res) => {
  const r = await pool.query('SELECT blocked_email FROM blocks WHERE blocker_email=$1', [req.user.email]);
  res.json(r.rows.map(x => x.blocked_email));
});

// MUTES
app.post('/api/mute', authMiddleware, async (req, res) => {
  await pool.query('INSERT INTO mutes(owner_email,room) VALUES($1,$2) ON CONFLICT DO NOTHING', [req.user.email, req.body.room]);
  res.json({ success: true });
});
app.post('/api/unmute', authMiddleware, async (req, res) => {
  await pool.query('DELETE FROM mutes WHERE owner_email=$1 AND room=$2', [req.user.email, req.body.room]);
  res.json({ success: true });
});
app.get('/api/mutes', authMiddleware, async (req, res) => {
  const r = await pool.query('SELECT room FROM mutes WHERE owner_email=$1', [req.user.email]);
  res.json(r.rows.map(x => x.room));
});

// FILE UPLOADS
app.post('/api/upload/avatar', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    const result = await uploadStream(req.file.buffer, {
      folder: 'kozlomax/avatars', resource_type: 'image',
      transformation: [{ width: 256, height: 256, crop: 'fill', gravity: 'face' }]
    });
    await pool.query('UPDATE users SET avatar_url=$1 WHERE email=$2', [result.secure_url, req.user.email]);
    res.json({ url: result.secure_url });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/upload/image', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    const result = await uploadStream(req.file.buffer, { folder: 'kozlomax/images', resource_type: 'image' });
    res.json({ url: result.secure_url });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/upload/audio', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    const result = await uploadStream(req.file.buffer, { folder: 'kozlomax/audio', resource_type: 'video' });
    res.json({ url: result.secure_url });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// MESSAGES
app.get('/api/messages/:room', authMiddleware, async (req, res) => {
  const r = await pool.query(
    'SELECT email,name,text,type,file_url,timestamp FROM messages WHERE room=$1 ORDER BY timestamp ASC LIMIT 200',
    [req.params.room]
  );
  res.json(r.rows);
});

// SOCKETS
io.on('connection', (socket) => {
  let myEmail = null;

  socket.on('auth', (email) => {
    myEmail = email;
    socket.join(`user:${email}`);
    if (!onlineUsers.has(email)) onlineUsers.set(email, { sockets: new Set(), statusMode: 'auto' });
    onlineUsers.get(email).sockets.add(socket.id);
    broadcastStatus(email, onlineUsers.get(email).statusMode);
  });

  socket.on('set status mode', async (mode) => {
    if (!myEmail || !['auto','invisible','dnd'].includes(mode)) return;
    if (onlineUsers.has(myEmail)) onlineUsers.get(myEmail).statusMode = mode;
    await pool.query('UPDATE users SET status_mode=$1 WHERE email=$2', [mode, myEmail]);
    broadcastStatus(myEmail, mode);
  });

  socket.on('join room', (room) => socket.join(room));

  socket.on('chat message', async (data) => {
    if (!data?.room || !data?.email) return;
    if (data.room.startsWith('dm_')) {
      const other = getOtherEmail(data.room, data.email);
      if (other) {
        const blocked = await pool.query(
          'SELECT id FROM blocks WHERE (blocker_email=$1 AND blocked_email=$2) OR (blocker_email=$2 AND blocked_email=$1)',
          [data.email, other]
        );
        if (blocked.rows.length) { socket.emit('message error', { error: 'blocked' }); return; }
      }
    }
    const msg = {
      room: data.room, email: data.email, name: data.name,
      text: data.text||null, type: data.type||'text', file_url: data.file_url||null,
      timestamp: new Date()
    };
    await pool.query(
      'INSERT INTO messages(room,email,name,text,type,file_url) VALUES($1,$2,$3,$4,$5,$6)',
      [msg.room, msg.email, msg.name, msg.text, msg.type, msg.file_url]
    );
    io.to(data.room).emit('chat message', msg);
    if (data.room.startsWith('dm_')) {
      const other = getOtherEmail(data.room, data.email);
      if (other) io.to(`user:${other}`).emit('new dm', { room: data.room, from: data.email, name: data.name, text: data.text, type: data.type });
    }
  });

  // WebRTC signaling
  socket.on('call:offer',   d => io.to(`user:${d.to}`).emit('call:incoming', d));
  socket.on('call:answer',  d => io.to(`user:${d.to}`).emit('call:answer', d));
  socket.on('call:ice',     d => io.to(`user:${d.to}`).emit('call:ice', d));
  socket.on('call:end',     d => io.to(`user:${d.to}`).emit('call:end', d));
  socket.on('call:decline', d => io.to(`user:${d.to}`).emit('call:declined', d));

  socket.on('disconnect', async () => {
    if (myEmail && onlineUsers.has(myEmail)) {
      onlineUsers.get(myEmail).sockets.delete(socket.id);
      if (onlineUsers.get(myEmail).sockets.size === 0) {
        const mode = onlineUsers.get(myEmail).statusMode;
        // Don't update last_seen if invisible — it would reveal when they were online
        if (mode !== 'invisible') {
          await pool.query('UPDATE users SET last_seen=NOW() WHERE email=$1', [myEmail]);
        }
        broadcastStatus(myEmail, mode);
      }
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('KozloMax запущен!'));
