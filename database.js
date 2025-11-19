const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.resolve(__dirname, 'auth.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        initDb();
    }
});

function initDb() {
    db.serialize(() => {
        // Admins Table (for dashboard access)
        db.run(`CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            google_id TEXT UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Whitelisted Devices Table
        db.run(`CREATE TABLE IF NOT EXISTS whitelisted_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_hash TEXT UNIQUE,
            user_name TEXT,
            label TEXT,
            provider_id INTEGER,
            added_by TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(provider_id) REFERENCES admins(id)
        )`);

        // Refresh Tokens Table (for admin sessions)
        db.run(`CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER,
            token TEXT,
            expires_at DATETIME,
            FOREIGN KEY(admin_id) REFERENCES admins(id)
        )`);
    });
}

module.exports = db;
