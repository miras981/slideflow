const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'slideflow_secret_2024';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

app.use(express.json({ limit: '50mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Init DB tables
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS presentations (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(255) NOT NULL,
      is_private BOOLEAN DEFAULT false,
      slides JSONB NOT NULL DEFAULT '[]',
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS likes (
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      presentation_id INTEGER REFERENCES presentations(id) ON DELETE CASCADE,
      PRIMARY KEY (user_id, presentation_id)
    );
    CREATE TABLE IF NOT EXISTS follows (
      follower_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      following_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY (follower_id, following_id)
    );
  `);
  console.log('DB ready');
}

// Auth middleware
function auth(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Не авторизован' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Токен недействителен' });
  }
}

// ===== AUTH ROUTES =====
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: 'Заполните все поля' });
    if (password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
    const exists = await pool.query('SELECT id FROM users WHERE email=$1 OR username=$2', [email, username]);
    if (exists.rows.length > 0) return res.status(400).json({ error: 'Email или имя уже используется' });
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email',
      [username, email, hash]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
    res.json({ user });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (!result.rows.length) return res.status(401).json({ error: 'Неверный email или пароль' });
    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Неверный email или пароль' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
    res.json({ user: { id: user.id, username: user.username, email: user.email } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, email FROM users WHERE id=$1', [req.user.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Не найден' });
    res.json({ user: result.rows[0] });
  } catch (e) {
    res.status(500).json({ error: 'Ошибка' });
  }
});

// ===== PRESENTATIONS =====
app.get('/api/presentations', auth, async (req, res) => {
  try {
    const { search } = req.query;
    let q = `SELECT p.*, u.username, u.id as author_id,
      (SELECT COUNT(*) FROM likes WHERE presentation_id=p.id) as likes_count,
      (SELECT COUNT(*) > 0 FROM likes WHERE presentation_id=p.id AND user_id=$1) as liked
      FROM presentations p JOIN users u ON p.user_id=u.id
      WHERE (p.is_private=false OR p.user_id=$1)`;
    const params = [req.user.id];
    if (search) { q += ` AND p.title ILIKE $2`; params.push(`%${search}%`); }
    q += ' ORDER BY p.created_at DESC';
    const result = await pool.query(q, params);
    res.json(result.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка' });
  }
});

app.get('/api/presentations/my', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*, u.username,
        (SELECT COUNT(*) FROM likes WHERE presentation_id=p.id) as likes_count,
        (SELECT COUNT(*) > 0 FROM likes WHERE presentation_id=p.id AND user_id=$1) as liked
        FROM presentations p JOIN users u ON p.user_id=u.id
        WHERE p.user_id=$1 ORDER BY p.created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: 'Ошибка' }); }
});

app.get('/api/presentations/following', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*, u.username,
        (SELECT COUNT(*) FROM likes WHERE presentation_id=p.id) as likes_count,
        (SELECT COUNT(*) > 0 FROM likes WHERE presentation_id=p.id AND user_id=$1) as liked
        FROM presentations p JOIN users u ON p.user_id=u.id
        WHERE p.user_id IN (SELECT following_id FROM follows WHERE follower_id=$1)
        AND p.is_private=false ORDER BY p.created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: 'Ошибка' }); }
});

app.get('/api/presentations/user/:uid', auth, async (req, res) => {
  try {
    const uid = req.params.uid;
    const result = await pool.query(
      `SELECT p.*, u.username,
        (SELECT COUNT(*) FROM likes WHERE presentation_id=p.id) as likes_count,
        (SELECT COUNT(*) > 0 FROM likes WHERE presentation_id=p.id AND user_id=$1) as liked
        FROM presentations p JOIN users u ON p.user_id=u.id
        WHERE p.user_id=$2 AND (p.is_private=false OR p.user_id=$1)
        ORDER BY p.created_at DESC`,
      [req.user.id, uid]
    );
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: 'Ошибка' }); }
});

app.post('/api/presentations', auth, async (req, res) => {
  try {
    const { title, is_private, slides } = req.body;
    const result = await pool.query(
      'INSERT INTO presentations (user_id, title, is_private, slides) VALUES ($1,$2,$3,$4) RETURNING *',
      [req.user.id, title || 'Без названия', !!is_private, JSON.stringify(slides || [])]
    );
    res.json(result.rows[0]);
  } catch (e) { res.status(500).json({ error: 'Ошибка' }); }
});

app.put('/api/presentations/:id', auth, async (req, res) => {
  try {
    const { title, is_private, slides } = req.body;
    const result = await pool.query(
      `UPDATE presentations SET title=$1, is_private=$2, slides=$3, updated_at=NOW()
       WHERE id=$4 AND user_id=$5 RETURNING *`,
      [title, !!is_private, JSON.stringify(slides), req.params.id, req.user.id]
    );
    if (!result.rows.length) return res.status(403).json({ error: 'Нет доступа' });
    res.json(result.rows[0]);
  } catch (e) { res.status(500).json({ error: 'Ошибка' }); }
});

app.delete('/api/presentations/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM presentations WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Ошибка' }); }
});

// ===== LIKES =====
app.post('/api/presentations/:id/like', auth, async (req, res) => {
  try {
    const pid = req.params.id;
    const uid = req.user.id;
    const exists = await pool.query('SELECT 1 FROM likes WHERE user_id=$1 AND presentation_id=$2', [uid, pid]);
    if (exists.rows.length) {
      await pool.query('DELETE FROM likes WHERE user_id=$1 AND presentation_id=$2', [uid, pid]);
    } else {
      await pool.query('INSERT INTO likes (user_id, presentation_id) VALUES ($1,$2)', [uid, pid]);
    }
    const count = await pool.query('SELECT COUNT(*) FROM likes WHERE presentation_id=$1', [pid]);
    res.json({ liked: !exists.rows.length, count: parseInt(count.rows[0].count) });
  } catch (e) { res.status(500).json({ error: 'Ошибка' }); }
});

// ===== FOLLOWS =====
app.post('/api/users/:id/follow', auth, async (req, res) => {
  try {
    const fid = req.params.id;
    const uid = req.user.id;
    if (fid == uid) return res.status(400).json({ error: 'Нельзя подписаться на себя' });
    const exists = await pool.query('SELECT 1 FROM follows WHERE follower_id=$1 AND following_id=$2', [uid, fid]);
    if (exists.rows.length) {
      await pool.query('DELETE FROM follows WHERE follower_id=$1 AND following_id=$2', [uid, fid]);
    } else {
      await pool.query('INSERT INTO follows (follower_id, following_id) VALUES ($1,$2)', [uid, fid]);
    }
    const followers = await pool.query('SELECT COUNT(*) FROM follows WHERE following_id=$1', [fid]);
    res.json({ following: !exists.rows.length, followers: parseInt(followers.rows[0].count) });
  } catch (e) { res.status(500).json({ error: 'Ошибка' }); }
});

// ===== USERS =====
app.get('/api/users/:id', auth, async (req, res) => {
  try {
    const uid = req.params.id;
    const result = await pool.query('SELECT id, username, email FROM users WHERE id=$1', [uid]);
    if (!result.rows.length) return res.status(404).json({ error: 'Не найден' });
    const user = result.rows[0];
    const followers = await pool.query('SELECT COUNT(*) FROM follows WHERE following_id=$1', [uid]);
    const following = await pool.query('SELECT COUNT(*) FROM follows WHERE follower_id=$1', [uid]);
    const isFollowing = await pool.query('SELECT 1 FROM follows WHERE follower_id=$1 AND following_id=$2', [req.user.id, uid]);
    res.json({
      ...user,
      followers_count: parseInt(followers.rows[0].count),
      following_count: parseInt(following.rows[0].count),
      is_following: isFollowing.rows.length > 0
    });
  } catch (e) { res.status(500).json({ error: 'Ошибка' }); }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

initDB().then(() => {
  app.listen(PORT, () => console.log(`SlideFlow running on port ${PORT}`));
}).catch(e => {
  console.error('DB init failed:', e.message);
  app.listen(PORT, () => console.log(`SlideFlow running on port ${PORT} (no db)`));
});
