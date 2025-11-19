const express = require('express');
const db = require('../database');
const { verifyAdmin } = require('../middleware/auth');

const router = express.Router();

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
const isValidHash = (hash) => {
    return typeof hash === 'string' && hash.length > 0 && hash.length < 500;
};

const isValidString = (str, maxLength = 100) => {
    return typeof str === 'string' && str.length <= maxLength;
};

// VERIFY DEVICE (for C++ EXE)
router.post('/verify-device', async (req, res) => {
    const { device_hash } = req.body;

    if (!device_hash || !isValidHash(device_hash)) {
        return res.status(400).json({ allowed: false, message: 'Invalid request' });
    }

    try {
        const device = await get(
            `SELECT wd.*, a.email as provider_email FROM whitelisted_devices wd 
             JOIN admins a ON wd.provider_id = a.id 
             WHERE wd.device_hash = ?`,
            [device_hash]
        );

        if (device) {
            return res.json({
                allowed: true,
                message: 'Device verified',
                provider: device.provider_email,
                user_name: device.user_name,
                label: device.label
            });
        } else {
            return res.json({
                allowed: false,
                message: 'Access denied'
            });
        }
    } catch (err) {
        console.error('[VERIFY_ERROR]', err.message);
        res.status(500).json({ allowed: false, message: 'Verification failed' });
    }
});

// ADD NEW DEVICE (Admin only)
router.post('/devices', verifyAdmin, async (req, res) => {
    const { device_hash, user_name, label } = req.body;

    // Validate inputs
    if (!device_hash || !isValidHash(device_hash)) {
        return res.status(400).json({ error: 'Invalid device information' });
    }

    if (user_name && !isValidString(user_name)) {
        return res.status(400).json({ error: 'Invalid user name' });
    }

    if (label && !isValidString(label, 200)) {
        return res.status(400).json({ error: 'Invalid label' });
    }

    try {
        const result = await run(
            `INSERT INTO whitelisted_devices (device_hash, user_name, label, provider_id, added_by) 
             VALUES (?, ?, ?, ?, ?)`,
            [device_hash, user_name || 'Unknown', label || '', req.admin.adminId, req.admin.email]
        );

        res.json({
            message: 'Device added successfully',
            deviceId: result.lastID
        });
    } catch (err) {
        console.error('[DEVICE_ADD_ERROR]', err.message);
        // Don't reveal database schema details
        if (err.message && err.message.includes('UNIQUE')) {
            return res.status(400).json({ error: 'Device already exists' });
        }
        res.status(500).json({ error: 'Failed to add device' });
    }
});

// ===== ADMIN ONLY ROUTES (require auth middleware) =====

// GET all whitelisted devices (Admin only - filtered by provider)
router.get('/devices', verifyAdmin, async (req, res) => {
    try {
        db.all(
            `SELECT * FROM whitelisted_devices WHERE provider_id = ? ORDER BY created_at DESC`,
            [req.admin.adminId],
            (err, rows) => {
                if (err) {
                    console.error('[DEVICE_FETCH_ERROR]', err.message);
                    return res.status(500).json({ error: 'Failed to retrieve devices' });
                }
                res.json({ devices: rows });
            }
        );
    } catch (err) {
        console.error('[DEVICE_FETCH_ERROR]', err.message);
        res.status(500).json({ error: 'Failed to retrieve devices' });
    }
});

// DELETE device from whitelist (Admin only - only own devices)
router.delete('/devices/:id', verifyAdmin, async (req, res) => {
    const { id } = req.params;

    // Validate ID
    if (!id || isNaN(parseInt(id))) {
        return res.status(400).json({ error: 'Invalid device ID' });
    }

    try {
        // Only allow deletion of devices added by this provider
        await run(`DELETE FROM whitelisted_devices WHERE id = ? AND provider_id = ? `, [id, req.admin.adminId]);
        res.json({ message: 'Device removed successfully' });
    } catch (err) {
        console.error('[DEVICE_DELETE_ERROR]', err.message);
        res.status(500).json({ error: 'Failed to remove device' });
    }
});

module.exports = router;
