const express = require('express');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const db = require('../database');
require('dotenv').config();

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'superrefreshsecret';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'YOUR_GOOGLE_CLIENT_ID';

const client = new OAuth2Client(GOOGLE_CLIENT_ID);

// Helper to run SQL
const run = (sql, params) => new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
        if (err) reject(err);
        else resolve(this);
    });
});

const get = (sql, params) => new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
        if (err) reject(err);
        else resolve(row);
    });
});

// ADMIN LOGIN (Google OAuth)
router.post('/admin-login', async (req, res) => {
    const { google_token } = req.body;

    if (!google_token) {
        return res.status(400).json({ error: 'Google token is required' });
    }

    try {
        // Verify Google Token
        const ticket = await client.verifyIdToken({
            idToken: google_token,
            audience: GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const googleId = payload['sub'];
        const email = payload['email'];

        // Check if admin exists
        let admin = await get(`SELECT * FROM admins WHERE google_id = ?`, [googleId]);

        if (!admin) {
            // Auto-register admin (you can restrict this to specific emails if needed)
            const result = await run(
                `INSERT INTO admins (email, google_id) VALUES (?, ?)`,
                [email, googleId]
            );
            admin = { id: result.lastID, email, google_id: googleId };
        }

        // Generate Tokens
        const accessToken = jwt.sign({ adminId: admin.id, email: admin.email }, JWT_SECRET, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ adminId: admin.id }, REFRESH_SECRET, { expiresIn: '7d' });

        // Store Refresh Token
        await run(`INSERT INTO refresh_tokens (admin_id, token, expires_at) VALUES (?, ?, datetime('now', '+7 days'))`, [admin.id, refreshToken]);

        res.json({ accessToken, refreshToken });

    } catch (err) {
        console.error('Login error:', err);
        res.status(401).json({ error: 'Authentication failed' });
    }
});

// REFRESH TOKEN
router.post('/refresh', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.sendStatus(401);

    try {
        const storedToken = await get(`SELECT * FROM refresh_tokens WHERE token = ?`, [refreshToken]);
        if (!storedToken) return res.sendStatus(403);

        jwt.verify(refreshToken, REFRESH_SECRET, (err, admin) => {
            if (err) return res.sendStatus(403);
            const accessToken = jwt.sign({ adminId: admin.adminId }, JWT_SECRET, { expiresIn: '15m' });
            res.json({ accessToken });
        });
    } catch (err) {
        console.error('Token refresh error:', err);
        res.status(500).json({ error: 'Token refresh failed' });
    }
});

// LOGOUT
router.post('/logout', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.sendStatus(200);

    try {
        await run(`DELETE FROM refresh_tokens WHERE token = ?`, [refreshToken]);
        res.json({ message: 'Logged out' });
    } catch (err) {
        console.error('Logout error:', err);
        res.status(500).json({ error: 'Logout failed' });
    }
});

module.exports = router;
