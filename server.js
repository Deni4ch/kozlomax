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

// Создаём таблицу пользователей (автоматически)
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`);

const JWT_SECRET = process.env.JWT_SECRET || 'temp-secret';

// === API РЕГИСТРАЦИЯ ===
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Заполни все поля' });

  try {
    const hashed = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, hashed]);
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: 'Такая почта уже есть' });
  }
});

// === API ЛОГИН ===
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Неверная почта или пароль' });
  }

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, email: user.email });
});

// === ПРОВЕРКА СЕССИИ ===
app.get('/api/me', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Нет токена' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ email: decoded.email });
  } catch (e) {
    res.status(401).json({ error: 'Сессия истекла' });
  }
});

io.on('connection', (socket) => {
  console.log('Пользователь в чате');
  socket.on('chat message', (data) => io.emit('chat message', data));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`KozloMax работает!`));
