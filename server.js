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

pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT,
    surname TEXT,
    age INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`);

pool.query(`
  CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    room TEXT NOT NULL,
    email TEXT NOT NULL,
    name TEXT,
    text TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`);

const JWT_SECRET = process.env.JWT_SECRET || 'kozlomax-super-secret-2026';

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
  } catch (e) {
    res.status(400).json({ error: 'Такая почта уже существует' });
  }
});

// Обновление профиля
app.post('/api/update-profile', async (req, res) => {
  const { token, name, surname, age } = req.body;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    await pool.query(
      'UPDATE users SET name = $1, surname = $2, age = $3 WHERE email = $4',
      [name, surname || null, age || null, decoded.email]
    );
    res.json({ success: true });
  } catch (e) {
    res.status(401).json({ error: 'Ошибка' });
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
  res.json({ token, email: user.email, name: user.name || user.email });
});

// Мои данные
app.get('/api/me', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Нет токена' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT email, name FROM users WHERE email = $1', [decoded.email]);
    res.json(result.rows[0]);
  } catch (e) {
    res.status(401).json({ error: 'Сессия истекла' });
  }
});

// Список всех пользователей для DM
app.get('/api/users', async (req, res) => {
  const result = await pool.query('SELECT email, name FROM users ORDER BY name');
  res.json(result.rows);
});

// История сообщений в комнате
app.get('/api/messages/:room', async (req, res) => {
  const { room } = req.params;
  const result = await pool.query(
    'SELECT email, name, text, timestamp FROM messages WHERE room = $1 ORDER BY timestamp ASC LIMIT 200',
    [room]
  );
  res.json(result.rows);
});

// Сокеты
io.on('connection', (socket) => {
  socket.on('join room', (room) => {
    socket.join(room);
  });

  socket.on('chat message', async (data) => {
    await pool.query(
      'INSERT INTO messages (room, email, name, text) VALUES ($1, $2, $3, $4)',
      [data.room, data.email, data.name, data.text]
    );
    io.to(data.room).emit('chat message', data);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('KozloMax — полностью исправлен и с DM!'));
