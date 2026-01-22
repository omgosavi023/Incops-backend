const express = require('express');
const router = express.Router();

// Import controller (where business logic lives)
const authController = require('../controllers/authController');

/**
 * ROUTES EXPLANATION:
 * router.METHOD('PATH', HANDLER_FUNCTION)
 * 
 * POST /api/auth/register - Create new user
 * POST /api/auth/login    - Authenticate user
 * GET  /api/auth/verify   - Verify token (protected)
 */

// Public routes
router.post('/register', authController.register);
router.post('/login', authController.login);

// Protected route (requires valid token)
router.get('/verify', authController.verifyToken);

module.exports = router;