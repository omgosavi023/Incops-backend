// IMPORTANT: Use bcryptjs (not bcrypt) if you're having issues
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');  // 👈 Changed to bcryptjs
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

//Import Middleware
const { verifyToken, requireRole } = require('./middleware/authMiddleware'); 

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Health check route
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Project INCOPs Backend is running',
        timestamp: new Date().toISOString()
    });
});

// Temporary "database" - in-memory users
const users = [
    {
        id: 1,
        username: 'admin',
        email: 'admin@incops.dev',
        password: '$2a$10$N9qo8uLOickgx2ZMRZoMye3Z5c4B6lF3LQeMp6cZJQ7TxAJsT8Y/W', // hash for "password123"
        role: 'admin'
    }
];

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        console.log('Login attempt for:', email);
        
        // Validate input
        if (!email || !password) {
            return res.status(400).json({ 
                error: 'Email and password are required' 
            });
        }
        
        // Find user
        const user = users.find(u => u.email === email);
        if (!user) {
            console.log('User not found:', email);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // For now, simple check (we'll use bcrypt.compare later)
        // Since we're using a pre-hashed password
        if (password === 'password123') {
            // Create JWT token
            const token = jwt.sign(
                { 
                    userId: user.id, 
                    username: user.username, 
                    email: user.email, 
                    role: user.role 
                },
                process.env.JWT_SECRET || 'incops-dev-secret',
                { expiresIn: '24h' }
            );
            
            return res.json({
                message: 'Login successful',
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role
                },
                token
            });
        }
        
        console.log('Invalid password for:', email);
        return res.status(401).json({ error: 'Invalid credentials' });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Protected route example
app.get('/api/dashboard', (req, res) => {
    // For now, simple check - will add proper JWT verification
    res.json({ 
        message: 'Welcome to Project INCOPs Dashboard',
        features: [
            'CI/CD Pipeline',
            'Container Security',
            'SAST/DAST Scanning',
            'Secrets Management',
            'Monitoring (Prometheus + Grafana + ELK)'
        ]
    });
});

// Simple registration endpoint (for testing)
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        if (!username || !email || !password) {
            return res.status(400).json({ 
                error: 'Username, email and password are required' 
            });
        }
        
        // Check if user exists
        const existingUser = users.find(u => u.email === email);
        if (existingUser) {
            return res.status(409).json({ error: 'User already exists' });
        }
        
        // Hash password using bcryptjs
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
            { 
                userId: newUser.id, 
                username: newUser.username, 
                email: newUser.email, 
                role: newUser.role 
            },
            process.env.JWT_SECRET || 'incops-dev-secret',
            { expiresIn: '24h' }
        );
        
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
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`🚀 Project INCOPs Backend running on port ${PORT}`);
    console.log(`📝 Health check: http://localhost:${PORT}/api/health`);
    console.log(`🔐 Login endpoint: POST http://localhost:${PORT}/api/login`);
    console.log(`👤 Test credentials: admin@incops.dev / password123`);
});
