const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Database connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  multipleStatements: true // Often helps with more complex SQLi demos
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('Connected to MySQL database.');
  
  // Auto-migrate schema: Ensure receiver_id exists for 1-on-1 chats
  db.query("SHOW COLUMNS FROM messages LIKE 'receiver_id'", (err, results) => {
    if (!err && results.length === 0) {
      db.query("ALTER TABLE messages ADD COLUMN receiver_id INT DEFAULT NULL", (err) => {
        if (!err) {
          db.query("ALTER TABLE messages ADD FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE");
          console.log('Successfully added receiver_id to messages table.');
        } else {
          console.error('Failed to add receiver_id:', err);
        }
      });
    }
  });
});

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
      if (err.code === 'ER_DUP_ENTRY') {
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
