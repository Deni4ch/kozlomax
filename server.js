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
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS name TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS surname TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS age INTEGER`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT`);

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

// Обновление профиля (включая username)
app.post('/api/update-profile', async (req, res) => {
  const { token, name, surname, age, username } = req.body;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    if (username) {
      const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
      if (!usernameRegex.test(username)) {
        return res.status(400).json({ error: 'Username: 3-20 символов, только буквы, цифры и _' });
      }
      const existing = await pool.query('SELECT email FROM users WHERE username = $1 AND email != $2', [username, decoded.email]);
      if (existing.rows.length > 0) {
        return res.status(400).json({ error: 'Этот username уже занят' });
      }
    }

    await pool.query(
      'UPDATE users SET name = $1, surname = $2, age = $3, username = $4 WHERE email = $5',
      [name, surname || null, age || null, username || null, decoded.email]
    );
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message || 'Ошибка' });
  }
});

// Логин
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Неверная почта или пароль' });
  }
  const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, email: user.email, name: user.name || user.email, username: user.username });
});

// Мои данные
app.get('/api/me', authMiddleware, async (req, res) => {
  const result = await pool.query('SELECT email, name, username FROM users WHERE email = $1', [req.user.email]);
  res.json(result.rows[0]);
});

// Поиск пользователей по username
app.get('/api/search', authMiddleware, async (req, res) => {
  const q = (req.query.q || '').trim().replace(/^@/, '');
  if (q.length < 2) return res.json([]);
  const result = await pool.query(
    `SELECT email, name, username FROM users 
     WHERE (username ILIKE $1 OR name ILIKE $1) AND email != $2
     LIMIT 10`,
    [`%${q}%`, req.user.email]
  );
  res.json(result.rows);
});

// Добавить контакт
app.post('/api/contacts/add', authMiddleware, async (req, res) => {
  const { contactEmail } = req.body;
  if (!contactEmail) return res.status(400).json({ error: 'Нет email контакта' });
  if (contactEmail === req.user.email) return res.status(400).json({ error: 'Нельзя добавить себя' });
  try {
    await pool.query(
      'INSERT INTO contacts (owner_email, contact_email) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [req.user.email, contactEmail]
    );
    res.json({ success: true });
  } catch {
    res.status(400).json({ error: 'Ошибка' });
  }
});

// Получить мои контакты
app.get('/api/contacts', authMiddleware, async (req, res) => {
  const result = await pool.query(
    `SELECT u.email, u.name, u.username FROM contacts c
     JOIN users u ON u.email = c.contact_email
     WHERE c.owner_email = $1
     ORDER BY u.name`,
    [req.user.email]
  );
  res.json(result.rows);
});

// История сообщений
app.get('/api/messages/:room', authMiddleware, async (req, res) => {
  const { room } = req.params;
  const result = await pool.query(
    'SELECT email, name, text, timestamp FROM messages WHERE room = $1 ORDER BY timestamp ASC LIMIT 200',
    [room]
  );
  res.json(result.rows);
});

// Сокеты
io.on('connection', (socket) => {
  socket.on('join room', (room) => socket.join(room));

  socket.on('chat message', async (data) => {
    const msg = { ...data, timestamp: new Date() };
    await pool.query(
      'INSERT INTO messages (room, email, name, text) VALUES ($1, $2, $3, $4)',
      [data.room, data.email, data.name, data.text]
    );
    io.to(data.room).emit('chat message', msg);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('KozloMax запущен!'));
