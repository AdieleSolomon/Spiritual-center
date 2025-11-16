import express from 'express';
import { createConnection, createPool } from 'mysql2/promise';
import bcrypt from 'bcryptjs';
const { hash, compare } = bcrypt;
import jwt from "jsonwebtoken";
const { sign, verify } = jwt;
import multer from 'multer';
import { join, extname } from 'path';
import cors from 'cors';
import { existsSync, mkdirSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

// ES module equivalent for __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config();

const app = express();

// Enhanced error handling
process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});

// Security middleware
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000 // increased for development
});
app.use(limiter);

// Create uploads directory if it doesn't exist
const uploadsDir = join(__dirname, 'uploads');
if (!existsSync(uploadsDir)) {
    mkdirSync(uploadsDir, { recursive: true });
    console.log('✅ Created uploads directory');
}

// CORS configuration - More permissive for development
app.use(cors({
    origin: true, // Allow all origins in development
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Handle preflight requests
app.options('*', cors());

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/uploads', express.static(uploadsDir));

// Serve static files from public directory (for frontend)
app.use(express.static(join(__dirname, 'public')));

// Database connection
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'spiritual_center',
    port: process.env.DB_PORT || 3306
};

// Initialize database connection pool
let pool;

async function initializeDatabase() {
    try {
        console.log('🔄 Initializing database...');
        
        // First connect without database to create it if needed
        const tempConnection = await createConnection({
            host: dbConfig.host,
            user: dbConfig.user,
            password: dbConfig.password,
            port: dbConfig.port
        });

        // Create database if it doesn't exist
        await tempConnection.execute(`CREATE DATABASE IF NOT EXISTS \`${dbConfig.database}\``);
        console.log(`✅ Database '${dbConfig.database}' created/verified`);
        await tempConnection.end();

        // Now connect to the database
        pool = createPool({
            ...dbConfig,
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 0,
            acquireTimeout: 60000,
            timeout: 60000
        });

        // Test connection
        const testConn = await pool.getConnection();
        console.log('✅ Database connection successful');
        await testConn.execute('SELECT 1');
        testConn.release();

        // Create tables if they don't exist
        await createTables();
        console.log('✅ Database initialized successfully');
        return true;
    } catch (error) {
        console.error('❌ Database initialization error:', error.message);
        console.log('💡 Troubleshooting tips:');
        console.log('   - Make sure MySQL server is running');
        console.log('   - Check database credentials in .env file');
        console.log('   - Verify MySQL port (default: 3306)');
        console.log('   - Ensure MySQL user has proper permissions');
        
        // Don't retry, just return false
        return false;
    }
}

async function createTables() {
    const connection = await pool.getConnection();
    
    try {
        // Users table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role ENUM('user', 'admin') DEFAULT 'user',
                is_approved BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Content table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS content (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                type ENUM('video', 'image', 'writeup') NOT NULL,
                file_url VARCHAR(500),
                content_text TEXT,
                is_public BOOLEAN DEFAULT FALSE,
                created_by INT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        // Prayer requests table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS prayer_requests (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NULL,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL,
                subject VARCHAR(255) NOT NULL,
                message TEXT NOT NULL,
                status ENUM('pending', 'read', 'responded') DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        `);

        // Check if admin user exists, if not create one
        const [adminUsers] = await connection.execute('SELECT id FROM users WHERE role = "admin"');
        if (adminUsers.length === 0) {
            const hashedPassword = await hash('admin123', 10);
            await connection.execute(
                'INSERT INTO users (username, email, password_hash, role, is_approved) VALUES (?, ?, ?, ?, ?)',
                ['admin', 'Wisdomadiele57@gmail.com', hashedPassword, 'admin', true]
            );
            console.log('✅ Default admin user created');
            console.log('📧 Admin email: Wisdomadiele57@gmail.com');
            console.log('🔑 Admin password: admin123');
        }

        console.log('✅ All tables created/verified successfully');
    } catch (error) {
        console.error('❌ Table creation error:', error);
        throw error;
    } finally {
        connection.release();
    }
}

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + extname(file.originalname);
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|mp4|avi|mov|pdf|doc|docx/;
        const fileExtname = allowedTypes.test(extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && fileExtname) {
            return cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only images, videos, and documents are allowed.'));
        }
    }
});

// JWT middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    verify(token, process.env.JWT_SECRET || 'spiritual_center_secret_2024', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Admin middleware
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// Database connection middleware
const requireDatabase = (req, res, next) => {
    if (!pool) {
        return res.status(503).json({ error: 'Database not available. Please try again later.' });
    }
    next();
};

// Routes

// Health check route
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        database: pool ? 'Connected' : 'Disconnected',
        environment: process.env.NODE_ENV || 'development'
    });
});

// Test routes
app.get('/api/test', (req, res) => {
    res.json({ 
        message: 'API is working!',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        version: '1.0.0'
    });
});

app.get('/api/test-db', requireDatabase, async (req, res) => {
    try {
        const connection = await pool.getConnection();
        const [rows] = await connection.execute('SELECT 1 as test');
        connection.release();
        res.json({ 
            message: 'Database connection successful', 
            data: rows,
            pool: true
        });
    } catch (error) {
        console.error('Database test error:', error);
        res.status(500).json({ error: 'Database connection failed: ' + error.message });
    }
});

// User registration
app.post('/api/register', requireDatabase, async (req, res) => {
    let connection;
    try {
        const { username, email, password } = req.body;
        
        console.log('Registration attempt:', { username, email });
        
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long' });
        }

        connection = await pool.getConnection();

        const [existing] = await connection.execute(
            'SELECT id FROM users WHERE email = ? OR username = ?',
            [email, username]
        );

        if (existing.length > 0) {
            return res.status(400).json({ error: 'User already exists with this email or username' });
        }

        const hashedPassword = await hash(password, 10);

        const [result] = await connection.execute(
            'INSERT INTO users (username, email, password_hash, is_approved) VALUES (?, ?, ?, ?)',
            [username, email, hashedPassword, false]
        );

        res.status(201).json({ 
            message: 'Registration successful. Please wait for admin approval.',
            userId: result.insertId 
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error during registration' });
    } finally {
        if (connection) connection.release();
    }
});

// User login
app.post('/api/login', requireDatabase, async (req, res) => {
    let connection;
    try {
        const { email, password } = req.body;
        
        console.log('Login attempt for email:', email);
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        connection = await pool.getConnection();

        const [users] = await connection.execute(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );

        if (users.length === 0) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        const user = users[0];

        // Check if approved (admin is always approved)
        if (!user.is_approved && user.role !== 'admin') {
            return res.status(400).json({ error: 'Account pending approval. Please contact administrator.' });
        }

        const validPassword = await compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        const token = sign(
            { 
                id: user.id, 
                username: user.username, 
                email: user.email, 
                role: user.role || 'user'
            },
            process.env.JWT_SECRET || 'spiritual_center_secret_2024',
            { expiresIn: '24h' }
        );

        console.log('Login successful for user:', user.email, 'Role:', user.role);

        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role || 'user'
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error during login' });
    } finally {
        if (connection) connection.release();
    }
});

// Get all content (requires authentication)
app.get('/api/content', requireDatabase, authenticateToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [content] = await connection.execute(`
            SELECT c.*, u.username as author 
            FROM content c 
            LEFT JOIN users u ON c.created_by = u.id 
            ORDER BY c.created_at DESC
        `);

        res.json(content);
    } catch (error) {
        console.error('Get content error:', error);
        res.status(500).json({ error: 'Failed to load content' });
    } finally {
        if (connection) connection.release();
    }
});

// Get public content
app.get('/api/content/public', requireDatabase, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [content] = await connection.execute(`
            SELECT c.*, u.username as author 
            FROM content c 
            LEFT JOIN users u ON c.created_by = u.id 
            WHERE c.is_public = TRUE
            ORDER BY c.created_at DESC
            LIMIT 20
        `);

        res.json(content);
    } catch (error) {
        console.error('Get public content error:', error);
        res.status(500).json({ error: 'Failed to load public content' });
    } finally {
        if (connection) connection.release();
    }
});

// Upload content (admin only)
app.post('/api/content', requireDatabase, authenticateToken, requireAdmin, upload.single('file'), async (req, res) => {
    let connection;
    try {
        const { title, description, type, content_text, is_public } = req.body;
        
        if (!title || !description || !type) {
            return res.status(400).json({ error: 'Title, description, and type are required' });
        }

        let fileUrl = null;
        if (req.file) {
            fileUrl = `/uploads/${req.file.filename}`;
        } else if (type !== 'writeup') {
            return res.status(400).json({ error: 'File is required for video and image content' });
        }

        if (type === 'writeup' && !content_text) {
            return res.status(400).json({ error: 'Content text is required for writeups' });
        }

        connection = await pool.getConnection();

        const [result] = await connection.execute(
            'INSERT INTO content (title, description, type, file_url, content_text, created_by, is_public) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [title, description, type, fileUrl, content_text || null, req.user.id, is_public === 'true']
        );

        res.status(201).json({ 
            message: 'Content uploaded successfully',
            contentId: result.insertId 
        });
    } catch (error) {
        console.error('Upload content error:', error);
        res.status(500).json({ error: 'Failed to upload content' });
    } finally {
        if (connection) connection.release();
    }
});

// Get users for admin (admin only)
app.get('/api/users', requireDatabase, authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [users] = await connection.execute(
            'SELECT id, username, email, role, is_approved, created_at FROM users ORDER BY created_at DESC'
        );

        res.json(users);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Failed to load users' });
    } finally {
        if (connection) connection.release();
    }
});

// Approve user (admin only)
app.put('/api/users/:id/approve', requireDatabase, authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        await connection.execute(
            'UPDATE users SET is_approved = TRUE WHERE id = ?',
            [req.params.id]
        );

        res.json({ message: 'User approved successfully' });
    } catch (error) {
        console.error('Approve user error:', error);
        res.status(500).json({ error: 'Failed to approve user' });
    } finally {
        if (connection) connection.release();
    }
});

// Prayer request submission
app.post('/api/prayer-requests', requireDatabase, async (req, res) => {
    let connection;
    try {
        const { name, email, subject, message, userId } = req.body;
        
        if (!name || !email || !subject || !message) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Basic email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Please provide a valid email address' });
        }

        connection = await pool.getConnection();

        const [result] = await connection.execute(
            'INSERT INTO prayer_requests (user_id, name, email, subject, message) VALUES (?, ?, ?, ?, ?)',
            [userId || null, name, email, subject, message]
        );

        res.status(201).json({ 
            message: 'Prayer request submitted successfully',
            requestId: result.insertId 
        });
    } catch (error) {
        console.error('Prayer request error:', error);
        res.status(500).json({ error: 'Failed to submit prayer request' });
    } finally {
        if (connection) connection.release();
    }
});

// Get prayer requests (admin only)
app.get('/api/prayer-requests', requireDatabase, authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [requests] = await connection.execute(`
            SELECT pr.*, u.username 
            FROM prayer_requests pr 
            LEFT JOIN users u ON pr.user_id = u.id 
            ORDER BY pr.created_at DESC
        `);

        res.json(requests);
    } catch (error) {
        console.error('Get prayer requests error:', error);
        res.status(500).json({ error: 'Failed to load prayer requests' });
    } finally {
        if (connection) connection.release();
    }
});

// Update prayer request status (admin only)
app.put('/api/prayer-requests/:id/status', requireDatabase, authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        const { status } = req.body;
        
        if (!['pending', 'read', 'responded'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }

        connection = await pool.getConnection();
        await connection.execute(
            'UPDATE prayer_requests SET status = ? WHERE id = ?',
            [status, req.params.id]
        );

        res.json({ message: 'Prayer request status updated successfully' });
    } catch (error) {
        console.error('Update prayer request status error:', error);
        res.status(500).json({ error: 'Failed to update prayer request status' });
    } finally {
        if (connection) connection.release();
    }
});

// Add missing routes that frontend expects
app.put('/api/prayer-requests/:id/read', requireDatabase, authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        await connection.execute(
            'UPDATE prayer_requests SET status = "read" WHERE id = ?',
            [req.params.id]
        );

        res.json({ message: 'Prayer request marked as read' });
    } catch (error) {
        console.error('Mark prayer as read error:', error);
        res.status(500).json({ error: 'Failed to update prayer request' });
    } finally {
        if (connection) connection.release();
    }
});

// Add missing DELETE routes
app.delete('/api/users/:id', requireDatabase, authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        await connection.execute('DELETE FROM users WHERE id = ?', [req.params.id]);
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    } finally {
        if (connection) connection.release();
    }
});

app.delete('/api/prayer-requests/:id', requireDatabase, authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        await connection.execute('DELETE FROM prayer_requests WHERE id = ?', [req.params.id]);
        res.json({ message: 'Prayer request deleted successfully' });
    } catch (error) {
        console.error('Delete prayer request error:', error);
        res.status(500).json({ error: 'Failed to delete prayer request' });
    } finally {
        if (connection) connection.release();
    }
});

// Get user profile
app.get('/api/profile', requireDatabase, authenticateToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [users] = await connection.execute(
            'SELECT id, username, email, role, is_approved, created_at FROM users WHERE id = ?',
            [req.user.id]
        );

        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(users[0]);
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({ error: 'Failed to load profile' });
    } finally {
        if (connection) connection.release();
    }
});

// Serve frontend for all other routes
app.get('*', (req, res) => {
    res.sendFile(join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large (max 10MB)' });
        }
    }
    console.error('Unhandled error:', error);
    res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler for API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({ error: 'API route not found' });
});

const PORT = process.env.PORT || 5000;

// Initialize database and start server
async function startServer() {
    console.log('🚀 Starting Spiritual Center Server...');
    
    // Initialize database (but don't block server start)
    initializeDatabase().then(success => {
        if (success) {
            console.log('✅ Database initialized successfully');
        } else {
            console.log('⚠️  Database not available, but server is running');
            console.log('💡 Some features may not work until database is connected');
        }
    });

    app.listen(PORT, '0.0.0.0', () => {
        console.log(`✅ Server running on port ${PORT}`);
        console.log(`📚 API Base URL: http://localhost:${PORT}/api`);
        console.log(`🌐 Frontend URL: http://localhost:${PORT}`);
        console.log(`🔍 Health Check: http://localhost:${PORT}/health`);
        console.log(`🗄️ Test DB: http://localhost:${PORT}/api/test-db`);
        console.log(`📁 Uploads directory: ${uploadsDir}`);
        console.log(`💡 Make sure MySQL is running and database credentials are correct`);
        console.log(`👤 Default Admin: Wisdomadiele57@gmail.com / admin123`);
    });
}

startServer().catch(error => {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
});