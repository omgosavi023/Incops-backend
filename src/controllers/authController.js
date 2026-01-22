const bcrypt = require('bcryptjs');  // For hashing passwords
const jwt = require('jsonwebtoken'); // For creating/verifying tokens

// Temporary "database" - will replace with real DB later
let users = [
    {
        id: 1,
        username: 'admin',
        email: 'admin@incops.dev',
        password: '$2a$10$YourHashedPasswordHere', // Will hash properly
        role: 'admin'
    }
];

// JWT Secret Key (store in .env in production!)
const JWT_SECRET = process.env.JWT_SECRET || 'incops-dev-secret-key-2024';

/**
 * CONTROLLER FUNCTIONS EXPLANATION:
 * Each function handles a specific HTTP request
 * req = Request object (contains data from client)
 * res = Response object (send data back to client)
 */

const authController = {
    // Register new user
    async register(req, res) {
        try {
            const { username, email, password } = req.body;
            
            // Validate input
            if (!username || !email || !password) {
                return res.status(400).json({ 
                    error: 'Username, email, and password are required' 
                });
            }
            
            // Check if user exists
            const existingUser = users.find(u => u.email === email);
            if (existingUser) {
                return res.status(409).json({ error: 'User already exists' });
            }
            
            // Hash password (security!)
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);
            
            // Create new user
            const newUser = {
                id: users.length + 1,
                username,
                email,
                password: hashedPassword,
                role: 'user',
                createdAt: new Date().toISOString()
            };
            
            users.push(newUser);
            
            // Create JWT token
            const token = jwt.sign(
                { userId: newUser.id, email: newUser.email, role: newUser.role },
                JWT_SECRET,
                { expiresIn: '24h' }
            );
            
            // Return success (don't send password back!)
            res.status(201).json({
                message: 'User registered successfully',
                user: {
                    id: newUser.id,
                    username: newUser.username,
                    email: newUser.email,
                    role: newUser.role
                },
                token
            });
            
        } catch (error) {
            console.error('Registration error:', error);
            res.status(500).json({ error: 'Registration failed' });
        }
    },
    
    // Login user
    async login(req, res) {
        try {
            const { email, password } = req.body;
            
            // Validate input
            if (!email || !password) {
                return res.status(400).json({ 
                    error: 'Email and password are required' 
                });
            }
            
            // Find user
            const user = users.find(u => u.email === email);
            if (!user) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            // Compare password with hashed password
            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            // Create JWT token
            const token = jwt.sign(
                { userId: user.id, email: user.email, role: user.role },
                JWT_SECRET,
                { expiresIn: '24h' }
            );
            
            // Return success
            res.json({
                message: 'Login successful',
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role
                },
                token
            });
            
        } catch (error) {
            console.error('Login error:', error);
            res.status(500).json({ error: 'Login failed' });
        }
    },
    
    // Verify token (protected route)
    verifyToken(req, res) {
        try {
            // Get token from Authorization header
            const authHeader = req.headers['authorization'];
            if (!authHeader) {
                return res.status(401).json({ error: 'No token provided' });
            }
            
            // Format: "Bearer <token>"
            const token = authHeader.split(' ')[1];
            
            // Verify token
            const decoded = jwt.verify(token, JWT_SECRET);
            
            // Return user info
            res.json({
                valid: true,
                user: decoded
            });
            
        } catch (error) {
            res.status(401).json({ 
                valid: false, 
                error: 'Invalid or expired token' 
            });
        }
    }
};

module.exports = authController;