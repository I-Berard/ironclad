const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const urllib = require('url');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretjwtkey_donotuseinprod';

app.use(cors());
app.use(express.json());

// Content Security Policy
// Requires bypassing to achieve XSS. Hint: cdnjs is allowed.
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:;"
  );
  next();
});

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

// ---------------------------------------------------------------------------
// MIDDLEWARE: Authenticate JWT
// VULNERABILITY (JWT alg:none): We manually decode the header and skip
// signature verification when alg is 'none'. A real implementation should
// always enforce a specific algorithm.
// ---------------------------------------------------------------------------
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Access denied' });

  // INTENTIONAL JWT ALGORITHM CONFUSION / ALG:NONE VULNERABILITY
  // Manually peek at the token header to allow 'none' algorithm
  try {
    const parts = token.split('.');
    if (parts.length < 2) return res.status(403).json({ error: 'Invalid token format' });

    const headerRaw = Buffer.from(parts[0], 'base64').toString('utf8');
    const header = JSON.parse(headerRaw);

    if (header.alg && header.alg.toLowerCase() === 'none') {
      // INTENTIONAL: Accept unsigned tokens — no signature check!
      const payloadRaw = Buffer.from(parts[1], 'base64').toString('utf8');
      req.user = JSON.parse(payloadRaw);
      console.log(`[JWT ALG:NONE] Accepted unsigned token for user: ${req.user.username}`);
      return next();
    }
  } catch (e) {
    // fall through to normal jwt.verify
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// ---------------------------------------------------------------------------
// AUTH ENDPOINTS
// ---------------------------------------------------------------------------

// POST /api/auth/signup
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
    const user = { id: results.insertId, username: username, bio: null, is_admin: 0 };
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
    res.status(201).json({ token, user, message: 'User created successfully' });
  });
});

// POST /api/auth/login
// VULNERABILITY (SQL Injection): Direct string concatenation instead of parameterized queries
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
      const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
      res.json({ token, user: { id: user.id, username: user.username, bio: user.bio } });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
});

// ---------------------------------------------------------------------------
// USERS ENDPOINT
// ---------------------------------------------------------------------------

app.get('/api/users', authenticateToken, (req, res) => {
  const query = 'SELECT id, username, bio FROM users';
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(results);
  });
});

// ---------------------------------------------------------------------------
// MESSAGE ENDPOINTS
// VULNERABILITY (IDOR on DMs): The server fetches DMs between ANY two users
// based on query parameters. If you know or enumerate user IDs you can read
// private conversations that don't belong to you.
// ---------------------------------------------------------------------------

app.get('/api/messages', authenticateToken, (req, res) => {
  const { chatWith } = req.query; // 'global' or user_id

  let query = '';
  let params = [];

  if (!chatWith || chatWith === 'global') {
    query = 'SELECT m.id, m.content, m.timestamp, u.username FROM messages m JOIN users u ON m.user_id = u.id WHERE m.receiver_id IS NULL ORDER BY m.timestamp ASC';
  } else {
    // INTENTIONAL IDOR VULNERABILITY
    // No ownership check: any authenticated user can fetch DMs between
    // arbitrary user IDs by manipulating chatWith and their own token.
    // e.g. GET /api/messages?chatWith=1 while forging a token as user 3
    // lets you read admin<->alice messages.
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

// GET /api/messages/:id — IDOR: read any message by ID, no ownership check
// VULNERABILITY (IDOR): Any authenticated user can fetch any message by its
// numeric ID, including private DMs between other users.
app.get('/api/messages/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  // INTENTIONAL IDOR VULNERABILITY — no WHERE user_id = req.user.id check
  const query = 'SELECT m.id, m.content, m.timestamp, m.user_id, m.receiver_id, u.username FROM messages m JOIN users u ON m.user_id = u.id WHERE m.id = ?';
  db.query(query, [id], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!results || results.length === 0) return res.status(404).json({ error: 'Message not found' });
    res.json(results[0]);
  });
});

// DELETE /api/messages/:id — IDOR: delete any message by ID, no ownership check
// VULNERABILITY (IDOR): Any authenticated user can delete any message.
app.delete('/api/messages/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  // INTENTIONAL IDOR VULNERABILITY — no ownership verification
  const query = 'DELETE FROM messages WHERE id = ?';
  db.query(query, [id], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (results.affectedRows === 0) return res.status(404).json({ error: 'Message not found' });
    res.json({ message: 'Message deleted' });
  });
});

// ---------------------------------------------------------------------------
// PROFILE ENDPOINTS
// ---------------------------------------------------------------------------

app.get('/api/profile/:username', (req, res) => {
  const { username } = req.params;
  const query = 'SELECT id, username, bio, is_admin, created_at FROM users WHERE username = ?';
  db.query(query, [username], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (results.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(results[0]);
  });
});

// PUT /api/profile
// VULNERABILITY (Mass Assignment): The server trusts client-supplied `is_admin`
// flag and writes it straight to the DB. Send {"bio":"...","is_admin":1} to
// promote yourself to admin.
app.put('/api/profile', authenticateToken, (req, res) => {
  const { bio, is_admin } = req.body;
  
  // INTENTIONAL STORED XSS VULNERABILITY — raw bio stored without sanitization
  // INTENTIONAL MASS ASSIGNMENT VULNERABILITY — client can set is_admin
  const fields = [];
  const values = [];

  if (bio !== undefined) { fields.push('bio = ?'); values.push(bio); }

  if (is_admin !== undefined) {
    // INTENTIONAL: We allow the client to set is_admin directly.
    // A secure implementation would never expose this field to user input.
    fields.push('is_admin = ?');
    values.push(is_admin ? 1 : 0);
    console.log(`[MASS ASSIGNMENT] User ${req.user.username} is attempting to set is_admin = ${is_admin}`);
  }

  if (fields.length === 0) {
    return res.status(400).json({ error: 'Nothing to update' });
  }

  values.push(req.user.id);
  const query = `UPDATE users SET ${fields.join(', ')} WHERE id = ?`;

  db.query(query, values, (err) => {
    if (err) return res.status(500).json({ error: 'Database error' });

    // Fetch updated record
    db.query('SELECT id, username, bio, is_admin FROM users WHERE id = ?', [req.user.id], (err2, rows) => {
      if (err2) return res.status(500).json({ error: 'Database error' });
      const updated = rows[0];
      const response = { message: 'Profile updated successfully', ...updated };
      if (updated.is_admin) {
        response.flag = process.env.FLAG_MASS_ASSIGN || 'FLAG{mass_assignment_grants_admin_powers}';
        response.admin_hint = 'You are now an admin. Check /api/admin/dashboard for more.';
      }
      res.json(response);
    });
  });
});

// ---------------------------------------------------------------------------
// NOTES ENDPOINTS (IDOR challenge)
// ---------------------------------------------------------------------------

// GET /api/notes — list own notes
app.get('/api/notes', authenticateToken, (req, res) => {
  const query = 'SELECT id, title, created_at FROM notes WHERE user_id = ?';
  db.query(query, [req.user.id], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(results);
  });
});

// POST /api/notes — create a new note
app.post('/api/notes', authenticateToken, (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) return res.status(400).json({ error: 'Title and content required' });
  const query = 'INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)';
  db.query(query, [req.user.id, title, content], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.status(201).json({ id: results.insertId, title, content });
  });
});

// GET /api/notes/:id — IDOR: read any note by ID without ownership check
// VULNERABILITY (IDOR): No check that the note belongs to req.user.
// Access note id=1 to find alice's flag.
app.get('/api/notes/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  // INTENTIONAL IDOR VULNERABILITY — missing: AND user_id = ?
  const query = 'SELECT n.id, n.title, n.content, n.created_at, u.username as owner FROM notes n JOIN users u ON n.user_id = u.id WHERE n.id = ?';
  db.query(query, [id], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!results || results.length === 0) return res.status(404).json({ error: 'Note not found' });
    res.json(results[0]);
  });
});

// ---------------------------------------------------------------------------
// SSRF ENDPOINT — /api/preview
// VULNERABILITY (SSRF): The block only checks for literal "localhost" /
// "127.0.0.1". Players can bypass it with 0.0.0.0, 0x7f000001, 127.1,
// decimal IP (2130706433), or DNS rebinding.
// Target: GET /api/admin/flag via SSRF to get the flag.
// ---------------------------------------------------------------------------
app.post('/api/preview', authenticateToken, (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target URL is required' });
  
  try {
    const parsed = urllib.parse(target);
    const client = parsed.protocol === 'https:' ? https : http;
    
    // "Security" check — intentionally bypassable
    if (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') {
      return res.status(403).json({ error: 'Localhost is blocked for security reasons!' });
    }

    client.get(target, (response) => {
      let data = '';
      response.on('data', chunk => data += chunk);
      response.on('end', () => {
        res.json({ preview: data.substring(0, 500) + (data.length > 500 ? '...' : '') });
      });
    }).on('error', (err) => {
      res.status(500).json({ error: 'Failed to fetch URL: ' + err.message });
    });
  } catch(e) {
    res.status(400).json({ error: 'Invalid URL' });
  }
});

// ---------------------------------------------------------------------------
// PATH TRAVERSAL ENDPOINT — /api/files
// VULNERABILITY (Path Traversal): The `name` query param is joined to an
// "uploads" base dir, but ../../ sequences are NOT stripped, allowing players
// to read arbitrary files on the server (e.g. /etc/passwd, ../.env).
// ---------------------------------------------------------------------------
const UPLOADS_DIR = path.join(__dirname, 'uploads');

// Ensure the uploads directory exists with some bait files
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  fs.writeFileSync(path.join(UPLOADS_DIR, 'welcome.txt'), 'Welcome to IronClad! Upload your files here.');
  fs.writeFileSync(path.join(UPLOADS_DIR, 'readme.txt'), 'This directory stores user-uploaded files. Enjoy!');
}

app.get('/api/files', authenticateToken, (req, res) => {
  const { name } = req.query;

  if (!name) {
    // List available files as a hint
    return res.json({ files: ['welcome.txt', 'readme.txt'], hint: 'Use ?name=<filename> to read a file.' });
  }

  // INTENTIONAL PATH TRAVERSAL VULNERABILITY
  // path.join is used but there is NO check that the resolved path stays
  // within UPLOADS_DIR. Players can use ../../../.env etc.
  const filePath = path.join(UPLOADS_DIR, name);

  console.log(`[FILE ACCESS] Requested: ${name} → Resolved: ${filePath}`);

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).json({ error: 'File not found: ' + err.message });
    }
    res.json({ name, content: data });
  });
});

// ---------------------------------------------------------------------------
// DEBUG ENDPOINT — /api/debug
// VULNERABILITY (Information Disclosure): Returns sensitive server internals
// including all environment variables (JWT secret, DB creds, flags, etc.).
// This endpoint is "hidden" but easily discoverable.
// ---------------------------------------------------------------------------
app.get('/api/debug', authenticateToken, (req, res) => {
  // INTENTIONAL INFORMATION DISCLOSURE VULNERABILITY
  console.log(`[DEBUG] Endpoint accessed by ${req.user.username}`);
  res.json({
    warning: 'This endpoint should never exist in production!',
    flag: process.env.FLAG_DEBUG || 'FLAG{debug_endpoints_leak_everything}',
    environment: process.env,          // Dumps ALL env vars including secrets
    nodeVersion: process.version,
    platform: process.platform,
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
    currentUser: req.user,
  });
});

// ---------------------------------------------------------------------------
// OPEN REDIRECT ENDPOINT — /api/redirect
// VULNERABILITY (Open Redirect): The `to` param is returned as a Location
// header with zero validation. Attackers can craft phishing links like:
//   https://ironclad.app/api/redirect?to=https://evil.com
// and steal tokens passed as URL fragments.
// ---------------------------------------------------------------------------
app.get('/api/redirect', (req, res) => {
  const { to } = req.query;

  if (!to) {
    return res.status(400).json({ error: 'Missing `to` parameter', hint: 'Use ?to=<url> to be redirected.' });
  }

  // INTENTIONAL OPEN REDIRECT VULNERABILITY — no allowlist check
  console.log(`[OPEN REDIRECT] Redirecting to: ${to}`);

  // Give a flag in a header so players know they hit the vulnerability
  res.setHeader('X-Flag', process.env.FLAG_OPEN_REDIRECT || 'FLAG{open_redirect_can_steal_tokens}');
  res.setHeader('X-Hint', 'Combine with XSS to steal auth tokens!');
  res.redirect(302, to);
});

// ---------------------------------------------------------------------------
// ADMIN ENDPOINTS
// ---------------------------------------------------------------------------

// Hidden Admin Flag — requires SSRF to reach (only accessible from localhost)
app.get('/api/admin/flag', (req, res) => {
  const ip = req.socket.remoteAddress || req.connection.remoteAddress;
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') {
    return res.json({ flag: process.env.FLAG_SSRF || 'FLAG{ssrfs_are_fun_when_you_bypass_filters}' });
  }
  return res.status(403).json({ error: 'Access denied. Admin only. Must access from localhost.' });
});

// Admin Dashboard — requires is_admin = 1 (achievable via mass assignment)
app.get('/api/admin/dashboard', authenticateToken, (req, res) => {
  // Re-read user from DB to check actual is_admin value
  db.query('SELECT id, username, is_admin FROM users WHERE id = ?', [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!rows || rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const dbUser = rows[0];
    if (!dbUser.is_admin) {
      return res.status(403).json({ error: 'Forbidden. Admins only.', hint: 'Are you sure you have admin privileges? Maybe you can acquire them somehow...' });
    }

    // Return all users (including passwords!) — realistic admin data leak
    db.query('SELECT id, username, password, bio, is_admin, created_at FROM users', (err2, users) => {
      if (err2) return res.status(500).json({ error: 'Database error' });
      res.json({
        message: 'Welcome to the admin dashboard!',
        flag: process.env.FLAG_MASS_ASSIGN || 'FLAG{mass_assignment_grants_admin_powers}',
        users,
        hint: 'All user passwords are stored in plaintext. Notice anything interesting?'
      });
    });
  });
});

// ---------------------------------------------------------------------------
// RATE LIMIT CHALLENGE — /api/auth/pin-verify
// VULNERABILITY (No Rate Limiting / Brute Force): A 4-digit PIN protects a
// flag, but there is no rate limiting so players can brute-force all 10,000
// combinations. The correct PIN is "1337".
// ---------------------------------------------------------------------------
app.post('/api/auth/pin-verify', authenticateToken, (req, res) => {
  const { pin } = req.body;
  const SECRET_PIN = process.env.SECRET_PIN || '1337';

  // INTENTIONAL: No rate limiting, no lockout — brute force away!
  if (String(pin) === SECRET_PIN) {
    return res.json({
      success: true,
      flag: process.env.FLAG_RATE_LIMIT || 'FLAG{no_rate_limit_means_brute_force_wins}',
      message: 'Correct PIN! You brute-forced your way in.'
    });
  }

  res.status(401).json({ success: false, error: 'Wrong PIN. Keep trying...' });
});

// ---------------------------------------------------------------------------
// JWT CHALLENGE ENDPOINT — /api/whoami
// Requires a valid or forged JWT. Returns the flag when alg:none is used.
// ---------------------------------------------------------------------------
app.get('/api/whoami', authenticateToken, (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  let usedAlgNone = false;
  try {
    const parts = token.split('.');
    const headerRaw = Buffer.from(parts[0], 'base64').toString('utf8');
    const header = JSON.parse(headerRaw);
    if (header.alg && header.alg.toLowerCase() === 'none') {
      usedAlgNone = true;
    }
  } catch (e) { /* ignore */ }

  const response = { user: req.user };

  if (usedAlgNone) {
    response.flag = process.env.FLAG_JWT || 'FLAG{alg_none_means_no_signature_needed}';
    response.message = '🎉 You exploited the JWT alg:none vulnerability!';
  }

  res.json(response);
});

// ---------------------------------------------------------------------------
// STATIC FILES + SPA FALLBACK
// ---------------------------------------------------------------------------
app.use(express.static(path.join(__dirname, 'public')));

app.get('/{*path}', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Ironclad Chat backend running on http://localhost:${port}`);
  console.log(`WARNING: This backend contains INTENTIONAL vulnerabilities for CTF/educational purposes only.`);
  console.log(`Vulnerabilities: SQLi, Stored XSS, SSRF, IDOR, JWT alg:none, Mass Assignment, Path Traversal, Info Disclosure, Open Redirect, Brute Force`);
});
