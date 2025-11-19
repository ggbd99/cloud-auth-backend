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

// Input validation helper
const isValidToken = (token) => {
    return typeof token === 'string' && token.length > 0 && token.length < 10000;
};

// ADMIN REGISTRATION (Google OAuth)
router.post('/register', async (req, res) => {
    const { google_token } = req.body;

    // Validate input
    if (!google_token || !isValidToken(google_token)) {
        return res.status(400).json({ error: 'Invalid request' });
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

        if (!googleId || !email) {
            return res.status(400).json({ error: 'Invalid authentication data' });
        }

        // Check if admin already exists
        let admin = await get(`SELECT * FROM admins WHERE google_id = ? OR email = ?`, [googleId, email]);

        if (admin) {
            return res.status(400).json({ error: 'Account already exists' });
        }

        // Register new admin
        const result = await run(
            `INSERT INTO admins (google_id, email) VALUES (?, ?)`,
            [googleId, email]
        );

        res.json({ success: true, message: 'Registration successful' });
    } catch (err) {
        // Log full error internally but don't expose details
        console.error('[REGISTRATION_ERROR]', err.message);
        res.status(500).json({ error: 'Registration failed. Please try again.' });
    }
});

// ADMIN LOGIN (Google OAuth)
router.post('/admin-login', async (req, res) => {
    const { google_token } = req.body;

    // Validate input
    if (!google_token || !isValidToken(google_token)) {
        return res.status(400).json({ error: 'Invalid request' });
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

        if (!googleId || !email) {
            return res.status(401).json({ error: 'Authentication failed' });
        }

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

        // Generate Tokens with shorter expiry for better security
        const accessToken = jwt.sign({ adminId: admin.id, email: admin.email }, JWT_SECRET, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ adminId: admin.id }, REFRESH_SECRET, { expiresIn: '7d' });

        // Store Refresh Token
        await run(`INSERT INTO refresh_tokens (admin_id, token, expires_at) VALUES (?, ?, datetime('now', '+7 days'))`, [admin.id, refreshToken]);

        res.json({ accessToken, refreshToken });

    } catch (err) {
        // Log error internally without exposing details
        console.error('[LOGIN_ERROR]', err.message);
        // Generic error - don't reveal if account exists or specific failure reason
        res.status(401).json({ error: 'Authentication failed' });
    }
});

// REFRESH TOKEN
router.post('/refresh', async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken || !isValidToken(refreshToken)) {
        return res.sendStatus(401);
    }

    try {
        const storedToken = await get(`SELECT * FROM refresh_tokens WHERE token = ?`, [refreshToken]);
        if (!storedToken) return res.sendStatus(403);

        jwt.verify(refreshToken, REFRESH_SECRET, (err, admin) => {
            if (err) return res.sendStatus(403);
            const accessToken = jwt.sign({ adminId: admin.adminId }, JWT_SECRET, { expiresIn: '15m' });
            res.json({ accessToken });
        });
    } catch (err) {
        console.error('[REFRESH_ERROR]', err.message);
        return res.sendStatus(403);
    }
});

// LOGOUT
router.post('/logout', async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken || !isValidToken(refreshToken)) {
        return res.sendStatus(200);
    }

    try {
        await run(`DELETE FROM refresh_tokens WHERE token = ?`, [refreshToken]);
        res.json({ message: 'Logged out successfully' });
    } catch (err) {
        console.error('[LOGOUT_ERROR]', err.message);
        // Don't reveal error details
        return res.sendStatus(200);
    }
});

module.exports = router;
