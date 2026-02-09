const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = "ford_secret_key";

/* SQLite DB */
const db = new sqlite3.Database('./ford.db', err => {
  if (err) console.error(err);
  else console.log('SQLite DB connected');
});

/* Create users table if not exists */
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

/* REGISTER */
app.post('/api/register', async (req, res) => {
  const { full_name, email, password } = req.body;
  if (!full_name || !email || !password)
    return res.status(400).json({ error: 'Missing fields' });

  db.get(
    'SELECT id FROM users WHERE email = ?',
    [email],
    async (err, row) => {
      if (row) {
        return res.status(409).json({ error: 'Email already registered' });
      }

      const hash = await bcrypt.hash(password, 10);
      db.run(
        'INSERT INTO users (full_name, email, password) VALUES (?,?,?)',
        [full_name, email, hash],
        () => res.json({ message: 'Account created successfully' })
      );
    }
  );
});

/* LOGIN */
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  db.get(
    'SELECT * FROM users WHERE email = ?',
    [email],
    async (err, user) => {
      if (!user)
        return res.status(401).json({ error: 'Invalid email or password' });

      const ok = await bcrypt.compare(password, user.password);
      if (!ok)
        return res.status(401).json({ error: 'Invalid email or password' });

      const token = jwt.sign(
        { id: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: '1h' }
      );

      res.json({
        token,
        user: {
          id: user.id,
          full_name: user.full_name,
          email: user.email
        }
      });
    }
  );
});

/* VERIFY TOKEN */
app.get('/api/verify-token', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.sendStatus(401);

  jwt.verify(auth.split(' ')[1], JWT_SECRET, err =>
    err ? res.sendStatus(401) : res.sendStatus(200)
  );
});

/* START SERVER */
app.listen(3000, () => {
  console.log('API running at http://localhost:3000');
});
