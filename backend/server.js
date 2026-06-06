const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Database connection
const dbFile = path.join(__dirname, 'database.sqlite');
const dbInstance = new sqlite3.Database(dbFile, (err) => {
  if (err) {
    console.error('Error connecting to SQLite:', err.message);
    return;
  }
  console.log('Connected to SQLite database.');
  
  // Enable foreign keys
  dbInstance.run('PRAGMA foreign_keys = ON;', (err) => {
    if (err) console.error('Failed to enable foreign keys:', err);
  });

  // Initialize schema
  const schemaPath = path.join(__dirname, '..', 'schema.sql');
  if (fs.existsSync(schemaPath)) {
    const schema = fs.readFileSync(schemaPath, 'utf8');
    dbInstance.exec(schema, (err) => {
      if (err) {
        console.error('Failed to initialize schema:', err);
      } else {
        console.log('Schema initialized.');
      }
    });
  }
});

// Wrapper to mimic mysql2's db.query API
const db = {
  query: function(sql, params, callback) {
    if (typeof params === 'function') {
      callback = params;
      params = [];
    }
    
    const queryType = sql.trim().toUpperCase().split(' ')[0];
    const isSelect = queryType === 'SELECT' || queryType === 'PRAGMA';

    if (isSelect) {
      dbInstance.all(sql, params, (err, rows) => {
        callback(err, rows);
      });
    } else {
      dbInstance.run(sql, params, function(err) {
        if (callback) {
          callback(err, err ? null : { insertId: this.lastID, affectedRows: this.changes });
        }
      });
    }
  }
};

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Access denied' });
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// --- AUTH ENDPOINTS ---

app.post('/api/auth/signup', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const query = 'INSERT INTO users (username, password) VALUES (?, ?)';
  db.query(query, [username, password], (err, results) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY' || (err.code === 'SQLITE_CONSTRAINT' && err.message.includes('UNIQUE'))) {
        return res.status(400).json({ error: 'Username already exists' });
      }
      return res.status(500).json({ error: 'Database error' });
    }
    
    // Auto-login upon signup
    const user = { id: results.insertId, username: username, bio: null };
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.status(201).json({ token, user, message: 'User created successfully' });
  });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  // INTENTIONAL SQL INJECTION VULNERABILITY
  // Direct string concatenation instead of parameterized queries
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  
  console.log(`Executing query: ${query}`); // Log the query to help students see the payload
  
  db.query(query, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (results.length > 0) {
      // The first result returned is logged in
      const user = results[0];
      const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '24h' });
      res.json({ token, user: { id: user.id, username: user.username, bio: user.bio } });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
});

// --- USERS ENDPOINT ---

app.get('/api/users', authenticateToken, (req, res) => {
  const query = 'SELECT id, username, bio FROM users';
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(results);
  });
});

// --- MESSAGE ENDPOINTS ---

app.get('/api/messages', authenticateToken, (req, res) => {
  const { chatWith } = req.query; // 'global' or user_id

  let query = '';
  let params = [];

  if (!chatWith || chatWith === 'global') {
    query = 'SELECT m.id, m.content, m.timestamp, u.username FROM messages m JOIN users u ON m.user_id = u.id WHERE m.receiver_id IS NULL ORDER BY m.timestamp ASC';
  } else {
    // 1-on-1 chat
    query = 'SELECT m.id, m.content, m.timestamp, u.username FROM messages m JOIN users u ON m.user_id = u.id WHERE (m.user_id = ? AND m.receiver_id = ?) OR (m.user_id = ? AND m.receiver_id = ?) ORDER BY m.timestamp ASC';
    params = [req.user.id, chatWith, chatWith, req.user.id];
  }

  db.query(query, params, (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(results);
  });
});

app.post('/api/messages', authenticateToken, (req, res) => {
  const { content, receiver_id } = req.body;
  if (!content) return res.status(400).json({ error: 'Message content is required' });
  
  // INTENTIONAL STORED XSS VULNERABILITY
  // We save the raw input directly without any sanitization
  const query = 'INSERT INTO messages (user_id, receiver_id, username, content) VALUES (?, ?, ?, ?)';
  const recvId = receiver_id || null;
  db.query(query, [req.user.id, recvId, req.user.username, content], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.status(201).json({ id: results.insertId, user_id: req.user.id, receiver_id: recvId, username: req.user.username, content });
  });
});

// --- PROFILE ENDPOINTS ---

app.get('/api/profile/:username', (req, res) => {
  const { username } = req.params;
  const query = 'SELECT id, username, bio, created_at FROM users WHERE username = ?';
  db.query(query, [username], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (results.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(results[0]);
  });
});

app.put('/api/profile', authenticateToken, (req, res) => {
  const { bio } = req.body;
  
  // INTENTIONAL STORED XSS VULNERABILITY
  // We save the raw bio directly without any sanitization
  const query = 'UPDATE users SET bio = ? WHERE id = ?';
  db.query(query, [bio, req.user.id], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ message: 'Profile updated successfully', bio });
  });
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Ironclad Chat backend running on http://localhost:${port}`);
  console.log(`WARNING: This backend contains intentional vulnerabilities (SQLi, Stored XSS). Do not use in production.`);
});
