const sqlite3 = require('sqlite3').verbose();

// Connect to database
const db = new sqlite3.Database('./auth.db', (err) => {
    if (err) {
        console.error('Database connection error:', err);
        return;
    }
    console.log('Connected to database');
});

// CHANGE THIS TO YOUR GMAIL ADDRESS
const adminEmail = 'your-email@gmail.com'; // ← CHANGE THIS!

// Add admin
db.run(
    'INSERT INTO admins (email) VALUES (?) ON CONFLICT(email) DO NOTHING',
    [adminEmail],
    function (err) {
        if (err) {
            console.error('Error adding admin:', err);
        } else {
            console.log('✅ Admin added successfully:', adminEmail);
        }
        db.close();
    }
);
