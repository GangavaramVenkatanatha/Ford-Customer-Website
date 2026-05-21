const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const SECRET = 'ford_customer_secret_key';

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database('ford.db');

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      full_name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      vehicle_model TEXT,
      color TEXT,
      trim TEXT,
      engine TEXT,
      delivery_address TEXT,
      phone TEXT,
      status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS contact_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      name TEXT,
      email TEXT,
      subject TEXT,
      message TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      error: 'Token required'
    });
  }

  const token = authHeader.split(' ')[1];

  jwt.verify(token, SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        error: 'Invalid token'
      });
    }

    req.user = user;
    next();
  });
}

app.post('/api/register', async (req, res) => {
  const { full_name, email, password } = req.body;

  if (!full_name || !email || !password) {
    return res.status(400).json({
      error: 'Fill all fields'
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      `
      INSERT INTO users (
        full_name,
        email,
        password
      )
      VALUES (?, ?, ?)
      `,
      [full_name, email, hashedPassword],
      function (err) {
        if (err) {
          return res.status(400).json({
            error: 'Email exists'
          });
        }

        res.json({
          success: true
        });
      }
    );
  } catch (error) {
    res.status(500).json({
      error: 'Server error'
    });
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  db.get(
    `
    SELECT *
    FROM users
    WHERE email = ?
    `,
    [email],
    async (err, user) => {
      if (err || !user) {
        return res.status(400).json({
          error: 'Invalid credentials'
        });
      }

      const valid = await bcrypt.compare(password, user.password);

      if (!valid) {
        return res.status(400).json({
          error: 'Invalid credentials'
        });
      }

      const token = jwt.sign(
        {
          id: user.id,
          email: user.email
        },
        SECRET,
        {
          expiresIn: '24h'
        }
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

app.get('/api/verify-token', authenticateToken, (req, res) => {
  res.json({
    success: true
  });
});

app.post('/api/orders', authenticateToken, (req, res) => {
  const {
    vehicle_model,
    color,
    trim,
    engine,
    delivery_address,
    phone
  } = req.body;

  db.run(
    `
    INSERT INTO orders (
      user_id,
      vehicle_model,
      color,
      trim,
      engine,
      delivery_address,
      phone
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
    [
      req.user.id,
      vehicle_model,
      color,
      trim,
      engine,
      delivery_address,
      phone
    ],
    function (err) {
      if (err) {
        return res.status(500).json({
          error: 'Order failed'
        });
      }

      res.json({
        success: true,
        orderId: this.lastID
      });
    }
  );
});

app.get('/api/orders', authenticateToken, (req, res) => {
  db.all(
    `
    SELECT *
    FROM orders
    WHERE user_id = ?
    ORDER BY created_at DESC
    `,
    [req.user.id],
    (err, rows) => {
      if (err) {
        return res.status(500).json({
          error: 'Failed'
        });
      }

      res.json({
        orders: rows
      });
    }
  );
});

app.put('/api/orders/:id', authenticateToken, (req, res) => {
  db.run(
    `
    UPDATE orders
    SET status = ?
    WHERE id = ?
      AND user_id = ?
    `,
    [req.body.status, req.params.id, req.user.id],
    function (err) {
      if (err) {
        return res.status(500).json({
          error: 'Update failed'
        });
      }

      res.json({
        success: true
      });
    }
  );
});

app.post('/api/contact-messages', (req, res) => {
  const { user_id, name, email, subject, message } = req.body;

  db.run(
    `
    INSERT INTO contact_messages (
      user_id,
      name,
      email,
      subject,
      message
    )
    VALUES (?, ?, ?, ?, ?)
    `,
    [user_id, name, email, subject, message],
    function (err) {
      if (err) {
        return res.status(500).json({
          error: 'Message failed'
        });
      }

      res.json({
        success: true
      });
    }
  );
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
