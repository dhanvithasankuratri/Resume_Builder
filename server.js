const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');

const app = express();
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const db = new Database(path.join(__dirname, 'app.db'));

// ---------- Database schema ----------
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS resumes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  title TEXT NOT NULL,
  data TEXT NOT NULL,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);`);

app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Auth ----------
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });
const sign = (u) => jwt.sign({ id: u.id, email: u.email }, SECRET, { expiresIn: '2h' });

app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!/^\S+@\S+\.\S+$/.test(email || '')) return res.status(400).json({ error: 'Valid email required' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be 6+ characters' });
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email))
    return res.status(409).json({ error: 'Email already registered' });
  const hash = await bcrypt.hash(password, 10);
  const info = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run(email, hash);
  res.status(201).json({ token: sign({ id: info.lastInsertRowid, email }), email });
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email || '');
  if (!user || !(await bcrypt.compare(password || '', user.password_hash)))
    return res.status(401).json({ error: 'Invalid email or password' });
  res.json({ token: sign(user), email: user.email });
});

// Middleware: verifies JWT and attaches user to request
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: 'Please log in again' }); }
}

// ---------- Resume CRUD (each user sees only their own) ----------
const parse = (r) => ({ id: r.id, title: r.title, updated_at: r.updated_at, ...JSON.parse(r.data) });

app.get('/api/resumes', auth, (req, res) => {
  const rows = db.prepare('SELECT * FROM resumes WHERE user_id = ? ORDER BY updated_at DESC').all(req.user.id);
  res.json(rows.map(parse));
});

app.post('/api/resumes', auth, (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required' });
  const info = db.prepare('INSERT INTO resumes (user_id, title, data) VALUES (?, ?, ?)')
    .run(req.user.id, name, JSON.stringify(req.body));
  res.status(201).json({ id: info.lastInsertRowid });
});

app.put('/api/resumes/:id', auth, (req, res) => {
  const info = db.prepare('UPDATE resumes SET title = ?, data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?')
    .run(req.body.name || 'Untitled', JSON.stringify(req.body), req.params.id, req.user.id);
  if (!info.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ id: Number(req.params.id) });
});

app.delete('/api/resumes/:id', auth, (req, res) => {
  db.prepare('DELETE FROM resumes WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ---------- ATS keyword scoring ----------
const STOP = new Set(['the','and','for','with','you','are','our','will','have','this','that','from','your','who','able','work','team','experience','strong','good','skills','must','should','including','etc','their','about','role','job']);
const words = (t) => (String(t).toLowerCase().match(/[a-z][a-z+#.]{1,}/g) || []);

app.post('/api/ats-score', auth, (req, res) => {
  const { resume, jobDescription } = req.body;
  if (!resume || !jobDescription) return res.status(400).json({ error: 'Resume and job description required' });
  const jd = [...new Set(words(jobDescription).filter(w => w.length > 2 && !STOP.has(w)))];
  const have = new Set(words(JSON.stringify(resume)));
  const matched = jd.filter(w => have.has(w));
  const missing = jd.filter(w => !have.has(w)).slice(0, 20);
  res.json({ score: jd.length ? Math.round(matched.length / jd.length * 100) : 0, matched, missing });
});

app.listen(process.env.PORT || 3000, () => console.log('Running at http://localhost:3000'));
