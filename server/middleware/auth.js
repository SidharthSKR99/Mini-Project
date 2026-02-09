/**
 * JWT Authentication Middleware
 */

const jwt = require('jsonwebtoken');

/**
 * Authenticate JWT token from Authorization header
 */
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired' });
        }
        return res.status(403).json({ error: 'Invalid token' });
    }
};

/**
 * Optional authentication - doesn't fail if no token
 */
const optionalAuth = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = decoded;
        } catch (error) {
            // Token invalid, but continue without user
            req.user = null;
        }
    } else {
        req.user = null;
    }
    next();
};

/**
 * Require Pro tier subscription
 */
const requirePro = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    if (req.user.tier !== 'pro' && req.user.tier !== 'enterprise') {
        return res.status(403).json({
            error: 'Pro subscription required',
            upgrade_url: '/pricing'
        });
    }
    next();
};

/**
 * Require Admin role
 */
const requireAdmin = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    if (req.user.role !== 'admin') {
        return res.status(403).json({
            error: 'Admin access required',
            message: 'You do not have permission to access this resource'
        });
    }
    next();
};

module.exports = {
    authenticateToken,
    optionalAuth,
    requirePro,
    requireAdmin
};
