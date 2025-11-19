const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const authRoutes = require('./routes/auth');
const deviceRoutes = require('./routes/device');
const db = require('./database');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security Headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// Trust proxy (important for Cloudflare)
app.set('trust proxy', true);

// CORS Configuration
const corsOptions = {
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:5173'],
    credentials: true,
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Body Parser
app.use(bodyParser.json());

// Rate Limiting - Device Verification (Critical Endpoint)
const deviceVerifyLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 30, // 30 requests per minute per IP
    message: { allowed: false, message: 'Too many verification attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    // Get real IP from Cloudflare
    keyGenerator: (req) => req.headers['cf-connecting-ip'] || req.ip
});

// Rate Limiting - Admin Login (Prevent Brute Force)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 login attempts per 15 minutes
    message: { error: 'Too many login attempts, please try again after 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.headers['cf-connecting-ip'] || req.ip
});

// Rate Limiting - Device Management (Add/Delete)
const deviceManagementLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 10, // 10 device operations per minute
    message: { error: 'Too many device operations, please slow down.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.headers['cf-connecting-ip'] || req.ip
});

// General API Rate Limiter
const generalLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 100, // 100 requests per minute per IP
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.headers['cf-connecting-ip'] || req.ip
});

// Apply rate limiters to specific routes
app.use('/api/verify-device', deviceVerifyLimiter);
app.use('/api/auth/admin-login', loginLimiter);
app.use('/api/devices', deviceManagementLimiter);
app.use('/api', generalLimiter); // General limiter for all other API routes

// Routes
app.use('/api/auth', authRoutes);
app.use('/api', deviceRoutes);

// Health Check
app.use('/health', (req, res) => {
    res.json({ status: 'ok' });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
