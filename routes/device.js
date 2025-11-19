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

// VERIFY DEVICE (for C++ EXE)
router.post('/verify-device', async (req, res) => {
    const { device_hash } = req.body;

    if (!device_hash) {
        return res.status(400).json({ allowed: false, message: 'Device hash is required' });
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
                message: 'Device verified successfully',
                provider: device.provider_email,
                user_name: device.user_name,
                label: device.label
            });
        } else {
            return res.json({
                allowed: false,
                message: 'Device not whitelisted'
            });
        }
    } catch (err) {
        console.error('Verification error:', err);
        res.status(500).json({ allowed: false, message: 'Server error occurred' });
    }
});

// ADD NEW DEVICE (Admin only)
router.post('/devices', verifyAdmin, async (req, res) => {
    const { device_hash, user_name, label } = req.body;

    if (!device_hash) {
        return res.status(400).json({ error: 'Device hash is required' });
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
        console.error('Device add error:', err);
        if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Device hash already exists' });
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
                    console.error('Device fetch error:', err);
                    return res.status(500).json({ error: 'Failed to fetch devices' });
                }
                res.json({ devices: rows });
            }
        );
    } catch (err) {
        console.error('Device fetch error (outer):', err);
        res.status(500).json({ error: 'Failed to fetch devices' });
    }
});

// DELETE device from whitelist (Admin only - only own devices)
router.delete('/devices/:id', verifyAdmin, async (req, res) => {
    const { id } = req.params;

    try {
        // Only allow deletion of devices added by this provider
        await run(`DELETE FROM whitelisted_devices WHERE id = ? AND provider_id = ? `, [id, req.admin.adminId]);
        res.json({ message: 'Device removed from whitelist' });
    } catch (err) {
        console.error('Device delete error:', err);
        res.status(500).json({ error: 'Failed to delete device' });
    }
});

module.exports = router;
