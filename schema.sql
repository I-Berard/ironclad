
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    bio TEXT,
    is_admin INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INT NOT NULL,
    receiver_id INT DEFAULT NULL,
    username VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Private notes table: used for the IDOR challenge
-- Each note belongs to a user; the server does NOT check ownership on read
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Insert a default admin user for testing the SQLi bypass
-- Password is 'admin123' (not hashed intentionally for demo simplicity)
INSERT OR IGNORE INTO users (username, password, bio, is_admin)
    VALUES ('admin', 'admin123', 'System Administrator', 1);

-- Insert a regular "victim" user whose DMs and notes can be stolen via IDOR
INSERT OR IGNORE INTO users (username, password, bio, is_admin)
    VALUES ('alice', 'alice_password', 'Just a normal user, nothing to see here...', 0);

-- Seed private notes — note id=1 holds the IDOR flag hint
INSERT OR IGNORE INTO notes (user_id, title, content)
    SELECT id, 'My Secret Flag',
           'Congratulations! FLAG{idor_lets_you_read_others_private_messages}'
    FROM users WHERE username = 'alice' LIMIT 1;

INSERT OR IGNORE INTO notes (user_id, title, content)
    SELECT id, 'Admin Credentials Backup',
           'admin / admin123 — do not share!'
    FROM users WHERE username = 'admin' LIMIT 1;

-- Seed a private DM from admin to alice that leaks the admin flag
INSERT OR IGNORE INTO messages (user_id, receiver_id, username, content)
    SELECT a.id, b.id, 'admin',
           'Alice, the server debug key is: FLAG{debug_endpoints_leak_everything} — keep it safe!'
    FROM users a, users b WHERE a.username = 'admin' AND b.username = 'alice';
