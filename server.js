const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Database Pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// ==================== HELPER FUNCTIONS ====================

async function dbQuery(sql, values) {
  const connection = await pool.getConnection();
  try {
    const [results] = await connection.execute(sql, values);
    return results;
  } finally {
    connection.release();
  }
}

function generateDeviceFingerprint(req) {
  const userAgent = req.headers['user-agent'] || '';
  const acceptLanguage = req.headers['accept-language'] || '';
  const combined = userAgent + acceptLanguage;
  return crypto.createHash('sha256').update(combined).digest('hex');
}

// ==================== DATABASE INIT ====================

async function initDatabase() {
  try {
    await dbQuery(`
      CREATE TABLE IF NOT EXISTS users (
        id INT PRIMARY KEY AUTO_INCREMENT,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role ENUM('admin', 'moderator', 'owner', 'user') DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `, []);

    await dbQuery(`
      CREATE TABLE IF NOT EXISTS active_devices (
        id INT PRIMARY KEY AUTO_INCREMENT,
        user_id INT NOT NULL,
        device_fingerprint VARCHAR(255) NOT NULL,
        device_name VARCHAR(255),
        ip_address VARCHAR(45),
        user_agent TEXT,
        session_token VARCHAR(255) UNIQUE NOT NULL,
        login_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX (user_id)
      )
    `, []);

    const users = await dbQuery('SELECT * FROM users WHERE username = "admin"', []);
    if (users.length === 0) {
      await dbQuery(
        'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
        ['admin', 'admin@test.com', 'password123', 'admin']
      );
      console.log('✓ Admin user created');
    }

    console.log('✓ Database initialized');
  } catch (error) {
    console.error('Database init error:', error.message);
  }
}

// ==================== ROUTES ====================

app.get('/api/test', (req, res) => {
  res.json({ message: 'Server berjalan dengan baik!' });
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username dan password harus diisi' });
    }

    const users = await dbQuery('SELECT * FROM users WHERE username = ?', [username]);
    
    if (users.length === 0) {
      return res.status(401).json({ error: 'Username atau password salah' });
    }

    const user = users[0];

    if (password !== user.password_hash) {
      return res.status(401).json({ error: 'Username atau password salah' });
    }

    const allowedRoles = ['admin', 'moderator', 'owner'];
    if (!allowedRoles.includes(user.role)) {
      return res.status(403).json({ error: 'Hanya admin/moderator/owner yang bisa login' });
    }

    const deviceFingerprint = generateDeviceFingerprint(req);
    const ipAddress = req.ip;
    const userAgent = req.headers['user-agent'];

    const existingSessions = await dbQuery(
      'SELECT * FROM active_devices WHERE user_id = ?',
      [user.id]
    );

    if (existingSessions.length > 0) {
      const existingDevice = existingSessions.find(s => s.device_fingerprint === deviceFingerprint);
      
      if (existingDevice) {
        const sessionToken = crypto.randomBytes(32).toString('hex');
        await dbQuery(
          'UPDATE active_devices SET session_token = ?, last_activity = NOW() WHERE id = ?',
          [sessionToken, existingDevice.id]
        );
        
        const token = jwt.sign(
          { userId: user.id, sessionId: existingDevice.id },
          process.env.JWT_SECRET,
          { expiresIn: '24h' }
        );
        
        return res.json({
          token,
          message: 'Login berhasil - device sama',
          userId: user.id,
          username: user.username,
          role: user.role
        });
      } else {
        await dbQuery('DELETE FROM active_devices WHERE user_id = ?', [user.id]);
      }
    }

    const sessionToken = crypto.randomBytes(32).toString('hex');
    const insertResult = await dbQuery(
      'INSERT INTO active_devices (user_id, device_fingerprint, ip_address, user_agent, session_token) VALUES (?, ?, ?, ?, ?)',
      [user.id, deviceFingerprint, ipAddress, userAgent, sessionToken]
    );

    const token = jwt.sign(
      { userId: user.id, sessionId: insertResult.insertId },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      message: 'Login berhasil',
      userId: user.id,
      username: user.username,
      role: user.role
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

async function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Token tidak ditemukan' });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const deviceFingerprint = generateDeviceFingerprint(req);

    const sessions = await dbQuery(
      'SELECT * FROM active_devices WHERE id = ? AND device_fingerprint = ?',
      [decoded.sessionId, deviceFingerprint]
    );

    if (sessions.length === 0) {
      return res.status(401).json({ error: 'Session tidak valid atau device berbeda' });
    }

    await dbQuery(
      'UPDATE active_devices SET last_activity = NOW() WHERE id = ?',
      [decoded.sessionId]
    );

    req.userId = decoded.userId;
    req.sessionId = decoded.sessionId;
    next();

  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token sudah expired' });
    }
    res.status(401).json({ error: 'Token tidak valid' });
  }
}

app.get('/api/dashboard', verifyToken, async (req, res) => {
  try {
    const users = await dbQuery('SELECT id, username, email, role FROM users WHERE id = ?', [req.userId]);
    
    if (users.length === 0) {
      return res.status(404).json({ error: 'User tidak ditemukan' });
    }

    const deviceInfo = await dbQuery(
      'SELECT device_name, ip_address, login_at, last_activity FROM active_devices WHERE id = ?',
      [req.sessionId]
    );

    res.json({
      message: 'Selamat datang di dashboard',
      user: users[0],
      deviceInfo: deviceInfo[0],
      timestamp: new Date()
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/logout', verifyToken, async (req, res) => {
  try {
    await dbQuery('DELETE FROM active_devices WHERE id = ?', [req.sessionId]);
    res.json({ message: 'Logout berhasil' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/devices', verifyToken, async (req, res) => {
  try {
    const devices = await dbQuery(
      'SELECT id, device_name, ip_address, login_at, last_activity FROM active_devices WHERE user_id = ?',
      [req.userId]
    );

    res.json({
      totalDevices: devices.length,
      devices: devices
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== START SERVER ====================

const PORT = process.env.PORT || 3000;

initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log('');
    console.log('╔════════════════════════════════════════╗');
    console.log(`║  Server berjalan di port ${PORT}         ║`);
    console.log('╚════════════════════════════════════════╝');
    console.log('');
  });
});

module.exports = app;
