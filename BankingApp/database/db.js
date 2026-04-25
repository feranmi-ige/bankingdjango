const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

// Connect to SQLite database
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error('Error connecting to database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        initializeDatabase();
    }
});

// Initialize the database with tables
function initializeDatabase() {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT,
            balance REAL DEFAULT 0
        )
    `, (err) => {
        if (err) {
            console.error('Error creating users table:', err.message);
        }
    });
}

module.exports = db;