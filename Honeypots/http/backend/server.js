const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 4000;

// Create logs directory if it doesn't exist
const logsDir = '/var/log/backend';
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Custom logging middleware for attacks
const logAttack = (req, res, next) => {
    const timestamp = new Date().toISOString();
    const logEntry = {
        timestamp,
        ip: req.ip || req.connection.remoteAddress,
        method: req.method,
        url: req.url,
        userAgent: req.get('User-Agent'),
        headers: req.headers,
        body: req.body,
        query: req.query
    };

    // Log to attacks.log for brute force detection
    const attackLog = `${timestamp} - IP: ${logEntry.ip} - ${req.method} ${req.url} - UA: ${logEntry.userAgent} - Body: ${JSON.stringify(req.body)}\n`;
    fs.appendFileSync('/var/log/nginx/attacks.log', attackLog);

    // Log detailed JSON for analysis
    fs.appendFileSync('/var/log/nginx/access.json', JSON.stringify(logEntry) + '\n');

    next();
};

// Apply attack logging to all requests
app.use(logAttack);

// Auth endpoints - these are honeypots with backdoor
app.post('/api/auth', (req, res) => {
    const { username, password } = req.body;
    
    console.log(`[HONEYPOT] Login attempt - Username: ${username}, Password: ${password}`);
    
    // Hidden backdoor for legitimate access
    if (username === 'admin' && password === 'SecureBackdoor2025!') {
        console.log(`[BACKDOOR] Legitimate admin access granted`);
        res.status(200).json({
            success: true,
            message: 'Access granted',
            token: 'admin-token-' + Date.now(),
            user: { username: 'admin', role: 'administrator' }
        });
        return;
    }
    
    // All other attempts are honeypot behavior
    res.status(401).json({
        success: false,
        message: 'Invalid credentials',
        error: 'Authentication failed'
    });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    console.log(`[HONEYPOT] Login attempt - Username: ${username}, Password: ${password}`);
    
    // Hidden backdoor for legitimate access
    if (username === 'admin' && password === 'SecureBackdoor2025!') {
        console.log(`[BACKDOOR] Legitimate admin access granted via /api/login`);
        res.status(200).json({
            success: true,
            message: 'Access granted',
            token: 'admin-token-' + Date.now(),
            user: { username: 'admin', role: 'administrator' }
        });
        return;
    }
    
    // All other attempts are honeypot behavior
    res.status(401).json({
        success: false,
        message: 'Invalid credentials',
        error: 'Authentication failed'
    });
});

// Admin endpoint
app.post('/admin', (req, res) => {
    const { username, password, action } = req.body;
    
    console.log(`[HONEYPOT] Admin login attempt - Username: ${username}, Password: ${password}, Action: ${action}`);
    
    // Always return unauthorized for honeypot behavior
    res.status(401).json({
        success: false,
        message: 'Access denied',
        error: 'Unauthorized access attempt'
    });
});

// Handle requests that come from nginx proxy without the /admin path
app.post('/', (req, res) => {
    const { username, password, action } = req.body;
    
    console.log(`[HONEYPOT] Root login attempt - Username: ${username}, Password: ${password}, Action: ${action}`);
    
    // Always return unauthorized for honeypot behavior
    res.status(401).json({
        success: false,
        message: 'Access denied',
        error: 'Unauthorized access attempt'
    });
});

// Generic login endpoints that attackers might try
const commonLoginPaths = [
    '/login',
    '/signin',
    '/auth',
    '/authenticate',
    '/wp-login.php',
    '/wp-admin',
    '/administrator',
    '/phpmyadmin',
    '/cpanel',
    '/webmail'
];

commonLoginPaths.forEach(path => {
    app.post(path, (req, res) => {
        console.log(`[HONEYPOT] Attack on ${path} - Body:`, req.body);
        res.status(404).json({
            success: false,
            message: 'Not Found',
            error: `Endpoint ${path} does not exist`
        });
    });

    app.get(path, (req, res) => {
        console.log(`[HONEYPOT] GET request to ${path}`);
        res.status(404).json({
            success: false,
            message: 'Not Found',
            error: `Endpoint ${path} does not exist`
        });
    });
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        service: 'CTI Backend',
        timestamp: new Date().toISOString()
    });
});

// Catch all other routes
app.use('*', (req, res) => {
    console.log(`[HONEYPOT] Unknown endpoint accessed: ${req.method} ${req.originalUrl}`);
    res.status(404).json({
        success: false,
        message: 'Endpoint not found',
        error: 'The requested resource does not exist'
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: err.message
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`[CTI Backend] Server running on port ${PORT}`);
    console.log(`[CTI Backend] Logging attacks to /var/log/nginx/attacks.log`);
    console.log(`[CTI Backend] Health check available at /health`);
});