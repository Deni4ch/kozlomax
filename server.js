const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(express.static('public'));
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      username TEXT UNIQUE,
      name TEXT,
      surname TEXT,
      age INTEGER,
      status_mode TEXT DEFAULT 'auto',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS name TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS surname TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS age INTEGER`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS status_mode TEXT DEFAULT 'auto'`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS contacts (
      id SERIAL PRIMARY KEY,
      owner_email TEXT NOT NULL,
      contact_email TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(owner_email, contact_email)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      room TEXT NOT NULL,
      email TEXT NOT NULL,
      name TEXT,
      text TEXT NOT NULL,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS room TEXT`);
  await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS name TEXT`);

  console.log('БД готова');
}

initDB().catch(console.error);

const JWT_SECRET = process.env.JWT_SECRET || 'kozlomax-super-secret-2026';

// Track online users: email -> { socketIds: Set, statusMode }
const onlineUsers = new Map();

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Нет токена' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Сессия истекла' });
  }
}

// Регистрация
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Заполни все поля' });
  if (password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) return res.status(400).json({ error: 'Неверный формат почты' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, hashed]);
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, email });
  } catch {
    res.status(400).json({ error: 'Такая почта уже существует' });
  }
});

// Обновление профиля
app.post('/api/update-profile', async (req, res) => {
  const { token, name, surname, age, username, status_mode } = req.body;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (username) {
      const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
      if (!usernameRegex.test(username))
        return res.status(400).json({ error: 'Username: 3-20 символов, только буквы, цифры и _' });
      const existing = await pool.query('SELECT email FROM users WHERE username = $1 AND email != $2', [username, decoded.email]);
      if (existing.rows.length > 0)
        return res.status(400).json({ error: 'Этот username уже занят' });
    }
    await pool.query(
      'UPDATE users SET name=$1, surname=$2, age=$3, username=$4, status_mode=COALESCE($5, status_mode) WHERE email=$6',
      [name, surname||null, age||null, username||null, status_mode||null, decoded.email]
    );
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message || 'Ошибка' });
  }
});

// Обновить только статус
app.post('/api/update-status', authMiddleware, async (req, res) => {
  const { status_mode } = req.body;
  const valid = ['auto', 'invisible', 'dnd'];
  if (!valid.includes(status_mode)) return res.status(400).json({ error: 'Неверный статус' });
  await pool.query('UPDATE users SET status_mode=$1 WHERE email=$2', [status_mode, req.user.email]);

  // Update in-memory and broadcast
  if (onlineUsers.has(req.user.email)) {
    onlineUsers.get(req.user.email).statusMode = status_mode;
  }
  broadcastStatus(req.user.email, status_mode);
  res.json({ success: true });
});

// Логин
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: 'Неверная почта или пароль' });
  const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, email: user.email, name: user.name||user.email, username: user.username, status_mode: user.status_mode||'auto' });
});

// Мои данные
app.get('/api/me', authMiddleware, async (req, res) => {
  const result = await pool.query('SELECT email, name, username, status_mode FROM users WHERE email=$1', [req.user.email]);
  res.json(result.rows[0]);
});

// Поиск пользователей
app.get('/api/search', authMiddleware, async (req, res) => {
  const q = (req.query.q||'').trim().replace(/^@/,'');
  if (q.length < 2) return res.json([]);
  const result = await pool.query(
    `SELECT email, name, username FROM users WHERE (username ILIKE $1 OR name ILIKE $1) AND email != $2 LIMIT 10`,
    [`%${q}%`, req.user.email]
  );
  res.json(result.rows);
});

// Добавить контакт (взаимно)
app.post('/api/contacts/add', authMiddleware, async (req, res) => {
  const { contactEmail } = req.body;
  if (!contactEmail) return res.status(400).json({ error: 'Нет email контакта' });
  if (contactEmail === req.user.email) return res.status(400).json({ error: 'Нельзя добавить себя' });
  const userCheck = await pool.query('SELECT email FROM users WHERE email=$1', [contactEmail]);
  if (!userCheck.rows.length) return res.status(404).json({ error: 'Пользователь не найден' });
  try {
    // Add both directions so both see the chat
    await pool.query('INSERT INTO contacts (owner_email, contact_email) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.user.email, contactEmail]);
    await pool.query('INSERT INTO contacts (owner_email, contact_email) VALUES ($1,$2) ON CONFLICT DO NOTHING', [contactEmail, req.user.email]);

    // Notify the contact via socket that they got a new contact
    const myInfo = await pool.query('SELECT email, name, username FROM users WHERE email=$1', [req.user.email]);
    io.to(`user:${contactEmail}`).emit('new contact', myInfo.rows[0]);

    res.json({ success: true });
  } catch {
    res.status(400).json({ error: 'Ошибка' });
  }
});

// Мои контакты
app.get('/api/contacts', authMiddleware, async (req, res) => {
  const result = await pool.query(
    `SELECT u.email, u.name, u.username, u.status_mode FROM contacts c
     JOIN users u ON u.email = c.contact_email
     WHERE c.owner_email = $1 ORDER BY u.name`,
    [req.user.email]
  );
  // Annotate with online status
  const contacts = result.rows.map(u => ({
    ...u,
    online: computeVisibleStatus(u.email, u.status_mode)
  }));
  res.json(contacts);
});

// История сообщений
app.get('/api/messages/:room', authMiddleware, async (req, res) => {
  const result = await pool.query(
    'SELECT email, name, text, timestamp FROM messages WHERE room=$1 ORDER BY timestamp ASC LIMIT 200',
    [req.params.room]
  );
  res.json(result.rows);
});

// Compute visible online status for a user
function computeVisibleStatus(email, statusMode) {
  const isOnline = onlineUsers.has(email) && onlineUsers.get(email).sockets.size > 0;
  if (statusMode === 'invisible') return false;
  if (statusMode === 'dnd') return isOnline ? 'dnd' : false;
  return isOnline; // auto
}

function broadcastStatus(email, statusMode) {
  const visible = computeVisibleStatus(email, statusMode);
  io.emit('user status', { email, online: visible });
}

// Сокеты
io.on('connection', (socket) => {
  let myEmail = null;

  socket.on('auth', (email) => {
    myEmail = email;
    socket.join(`user:${email}`);
    if (!onlineUsers.has(email)) onlineUsers.set(email, { sockets: new Set(), statusMode: 'auto' });
    onlineUsers.get(email).sockets.add(socket.id);
    // Broadcast online
    broadcastStatus(email, onlineUsers.get(email).statusMode);
  });

  socket.on('set status mode', async (mode) => {
    if (!myEmail) return;
    const valid = ['auto','invisible','dnd'];
    if (!valid.includes(mode)) return;
    if (onlineUsers.has(myEmail)) onlineUsers.get(myEmail).statusMode = mode;
    await pool.query('UPDATE users SET status_mode=$1 WHERE email=$2', [mode, myEmail]);
    broadcastStatus(myEmail, mode);
  });

  socket.on('join room', (room) => socket.join(room));

  socket.on('chat message', async (data) => {
    const msg = { ...data, timestamp: new Date() };
    await pool.query(
      'INSERT INTO messages (room, email, name, text) VALUES ($1,$2,$3,$4)',
      [data.room, data.email, data.name, data.text]
    );
    io.to(data.room).emit('chat message', msg);

    // Notify users in their personal rooms (for contacts who haven't opened chat yet)
    if (data.room.startsWith('dm_')) {
      const emailPart = data.room.slice(3); // remove 'dm_'
      const parts = emailPart.split('___');
      parts.forEach(email => {
        io.to(`user:${email}`).emit('new dm', { room: data.room, from: data.email, name: data.name });
      });
    }
  });

  socket.on('disconnect', () => {
    if (myEmail && onlineUsers.has(myEmail)) {
      onlineUsers.get(myEmail).sockets.delete(socket.id);
      if (onlineUsers.get(myEmail).sockets.size === 0) {
        broadcastStatus(myEmail, onlineUsers.get(myEmail).statusMode);
      }
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('KozloMax запущен!'));
