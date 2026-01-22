const jwt = require('jsonwebtoken');

/**
 * JWT Authentication Middleware
 * Verifies token from Authorization header
 */
const verifyToken = (req, res, next) => {
    // Get token from header
    const authHeader = req.headers['authorization'];
    
    if (!authHeader) {
        return res.status(401).json({ 
            error: 'Access denied. No token provided.',
            code: 'NO_TOKEN'
        });
    }
    
    // Check if header has "Bearer " prefix
    if (!authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ 
            error: 'Invalid token format. Use: Bearer <token>',
            code: 'INVALID_FORMAT'
        });
    }
    
    // Extract token (remove "Bearer " prefix)
    const token = authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ 
            error: 'Access denied. Token missing.',
            code: 'TOKEN_MISSING'
        });
    }
    
    try {
        // Verify token with secret key
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        
        // Attach user data to request object
        req.user = verified;
        
        // Log for debugging (remove in production)
        console.log(`✅ Token verified for user: ${verified.email} (${verified.role})`);
        
        // Continue to next middleware/route
        next();
        
    } catch (error) {
        console.error('❌ Token verification failed:', error.message);
        
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                error: 'Token expired. Please login again.',
                code: 'TOKEN_EXPIRED'
            });
        }
        
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ 
                error: 'Invalid token.',
                code: 'INVALID_TOKEN'
            });
        }
        
        return res.status(401).json({ 
            error: 'Authentication failed.',
            code: 'AUTH_FAILED'
        });
    }
};

/**
 * Role-Based Access Control Middleware
 * Checks if user has required role
 */
const requireRole = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'User not authenticated' });
        }
        
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ 
                error: `Access denied. Required roles: ${roles.join(', ')}`,
                userRole: req.user.role
            });
        }
        
        next();
    };
};

module.exports = {
    verifyToken,
    requireRole
};
