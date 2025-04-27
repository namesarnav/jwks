/*--------------------------------------------------------------------- //

Arnav Verma
CSCE 3550
11627633

Enhanced JWKS Server with AES encryption, user registration, authentication logging,
and rate limiting.

I have used AI in my project mainly for documentation and adding comments in the code for better understanding 
Prompt: "Add comments to the code explaining the functionality of each function and module"
//---------------------------------------------------------------------- */ 

/**
 * JWKS (JSON Web Key Set) Server Implementation
 * This server provides endpoints for JWT authentication and JWKS key management
 * with support for both valid and expired keys stored in SQLite database.
 * 
 * Enhancements:
 * - AES encryption for private keys in database
 * - User registration with Argon2 password hashing
 * - Authentication request logging
 * - Rate limiting for authentication requests
 */

const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { pem2jwk } = require('pem-jwk');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const argon2 = require('argon2');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());

// Environment variables
const AES_KEY = process.env.NOT_MY_KEY || 'default_development_key_do_not_use_in_production';

// Database setup
const dbPath = 'totally_not_my_privateKeys.db';
const db = new sqlite3.Database(dbPath);

/**
 * Initialize the database by creating all required tables
 */
db.serialize(() => {
  // Keys table
  db.run(`
    CREATE TABLE IF NOT EXISTS keys(
      kid INTEGER PRIMARY KEY AUTOINCREMENT,
      key BLOB NOT NULL,
      exp INTEGER NOT NULL
    )
  `);
  
  // Users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      email TEXT NOT NULL,
      date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      last_login TIMESTAMP
    )
  `);
  
  // Authentication logs table
  db.run(`
    CREATE TABLE IF NOT EXISTS auth_logs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      request_ip TEXT NOT NULL,
      request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      user_id INTEGER,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
});

/**
 * Encrypt data using AES-256-GCM
 * @param {string} text - Text to encrypt
 * @returns {Object} Object containing iv, encrypted data, and auth tag
 */
function encryptData(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(AES_KEY), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return {
    iv: iv.toString('hex'),
    encryptedData: encrypted,
    authTag
  };
}

/**
 * Decrypt data using AES-256-GCM
 * @param {Object} encryptedData - Object containing iv, encrypted data, and auth tag
 * @returns {string} Decrypted text
 */
function decryptData(encryptedData) {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    Buffer.from(AES_KEY),
    Buffer.from(encryptedData.iv, 'hex')
  );
  decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
  let decrypted = decipher.update(encryptedData.encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

/**
 * Generates an RSA key pair with specified expiry timestamp
 * @param {number} expiry - Expiry timestamp in seconds (Unix timestamp)
 * @returns {Object} Object containing public/private keys and expiry
 */
function generateKeyPair(expiry) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKey, privateKey, expiry };
}

/**
 * Store a key in the database with AES encryption
 * @param {string} privateKey - Private key in PEM format
 * @param {number} expiry - Expiry timestamp
 * @returns {Promise} Promise that resolves with the key ID
 */

function storeKey(privateKey, expiry) {
  return new Promise((resolve, reject) => {
    // Encrypt the private key before storing
    const encryptedKey = encryptData(privateKey);
    const keyData = JSON.stringify(encryptedKey);
    
    const stmt = db.prepare('INSERT INTO keys (key, exp) VALUES (?, ?)');
    stmt.run(keyData, expiry, function(err) {
      if (err) {
        reject(err);
      } else {
        resolve(this.lastID); // Return the inserted key ID
      }
    });
    stmt.finalize();
  });
}

/**
 * Retrieve and decrypt a key from the database
 * @param {number} kid - Key ID
 * @returns {Promise} Promise that resolves with the decrypted private key
 */
function getKey(kid) {
  return new Promise((resolve, reject) => {
    db.get('SELECT key FROM keys WHERE kid = ?', [kid], (err, row) => {
      if (err) {
        reject(err);
      } else if (!row) {
        reject(new Error('Key not found'));
      } else {
        try {
          const encryptedKey = JSON.parse(row.key);
          const decryptedKey = decryptData(encryptedKey);
          resolve(decryptedKey);
        } catch (error) {
          reject(error);
        }
      }
    });
  });
}

/**
 * Initialize the database with valid and expired keys if not already present
 */
async function initializeKeys() {
  // Check if keys already exist
  db.get('SELECT COUNT(*) as count FROM keys', async (err, row) => {
    if (err) {
      console.error('Error checking keys:', err);
      return;
    }

    if (row.count === 0) {
      // Calculate current time and expiry timestamps
      const now = Math.floor(Date.now() / 1000);
      const validExpiry = now + 3600;    // Valid for 1 hour from now
      const expiredExpiry = now - 3600;  // Expired 1 hour ago

      // Generate and store valid key
      const validKey = generateKeyPair(validExpiry);
      await storeKey(validKey.privateKey, validExpiry);

      // Generate and store expired key
      const expiredKey = generateKeyPair(expiredExpiry);
      await storeKey(expiredKey.privateKey, expiredExpiry);
      
      console.log('Keys initialized successfully');
    }
  });
}

// Initialize keys on server start
initializeKeys();

/**
 * Register a new user with Argon2 password hashing
 * @param {string} username - User's username
 * @param {string} password - User's password
 * @param {string} email - User's email
 * @returns {Promise} Promise that resolves with the user ID and generated password
 */
async function registerUser(username, email) {
  // Generate a secure password using UUIDv4
  const password = uuidv4();
  
  // Hash the password using Argon2
  const hashedPassword = await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 16384,  // 16 MB
    timeCost: 3,        // 3 iterations
    parallelism: 2      // 2 parallel threads
  });
  
  return new Promise((resolve, reject) => {
    const stmt = db.prepare('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)');
    stmt.run(username, hashedPassword, email, function(err) {
      if (err) {
        reject(err);
      } else {
        resolve({ userId: this.lastID, password });
      }
    });
    stmt.finalize();
  });
}

/**
 * Log an authentication request
 * @param {string} ip - Request IP address
 * @param {number|null} userId - User ID (if authenticated)
 * @returns {Promise} Promise that resolves when the log is created
 */
function logAuthRequest(ip, userId = null) {
  return new Promise((resolve, reject) => {
    const stmt = db.prepare('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)');
    stmt.run(ip, userId, function(err) {
      if (err) {
        reject(err);
      } else {
        resolve(this.lastID);
      }
    });
    stmt.finalize();
  });
}

/**
 * Rate limiter middleware - Limits requests to 10 per second
 */
const authRateLimiter = rateLimit({
  windowMs: 1000, // 1 second
  max: 10, // Limit each IP to 10 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: (req, res) => {
    res.status(429).json({
      error: 'Too many requests',
      message: 'Please try again later'
    });
  }
});

/**
 * Handle OPTIONS requests for CORS preflight
 * Returns 200 OK with appropriate CORS headers
 */
app.options('*', (req, res) => {
  res.status(200).send();
});

/**
 * Middleware for /auth endpoint to handle HTTP methods
 * Only allows POST and OPTIONS methods
 * Returns 405 Method Not Allowed for other methods
 */
app.all('/auth', (req, res, next) => {
  const allowedMethods = ['POST', 'OPTIONS'];
  if (!allowedMethods.includes(req.method)) {
    res.setHeader('Allow', allowedMethods.join(', '));
    return res.status(405).json({ error: 'Method not allowed' });
  }
  next();
});

/**
 * Authentication endpoint - Issues JWTs
 * Apply rate limiting to this endpoint
 */
app.post('/auth', authRateLimiter, async (req, res) => {
  try {
    // Log authentication request
    const clientIp = req.ip || req.connection.remoteAddress;
    await logAuthRequest(clientIp);
    
    const useExpired = req.query.expired !== undefined;
    const currentTime = Math.floor(Date.now() / 1000);
    
    // Query for an appropriate key based on expiry
    let query;
    if (useExpired) {
      query = 'SELECT kid, key, exp FROM keys WHERE exp < ? ORDER BY kid DESC LIMIT 1';
    } else {
      query = 'SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid DESC LIMIT 1';
    }
    
    db.get(query, [currentTime], async (err, key) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      
      if (!key) {
        return res.status(404).json({ error: 'Key not found' });
      }
      
      try {
        // Decrypt the private key
        const encryptedKey = JSON.parse(key.key);
        const decryptedKey = decryptData(encryptedKey);
        
        // Create JWT payload with subject and expiry
        const payload = {
          sub: 'user123',
          iat: Math.floor(Date.now() / 1000),
          exp: key.exp
        };

        // Sign the JWT using RS256 algorithm and include the key ID
        const token = jwt.sign(payload, decryptedKey, {
          algorithm: 'RS256',
          header: { kid: key.kid.toString() }
        });
        
        res.status(200).json({ token });
      } catch (error) {
        console.error('JWT signing error:', error);
        res.status(500).json({ error: 'Error signing token' });
      }
    });
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * User registration endpoint
 */
app.post('/register', async (req, res) => {
  try {
    const { username, email } = req.body;
    
    // Validate input
    if (!username || !email) {
      return res.status(400).json({ error: 'Username and email are required' });
    }
    
    // Register the user
    const result = await registerUser(username, email);
    
    // Return the generated password
    res.status(201).json({ password: result.password });
  } catch (error) {
    console.error('Registration error:', error);
    
    // Handle duplicate username
    if (error.message && error.message.includes('UNIQUE constraint failed')) {
      return res.status(409).json({ error: 'Username already exists' });
    }
    
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * Middleware for JWKS endpoint to handle HTTP methods
 * Only allows GET and OPTIONS methods
 * Returns 405 Method Not Allowed for other methods
 */
app.all('/.well-known/jwks.json', (req, res, next) => {
  const allowedMethods = ['GET', 'OPTIONS'];
  if (!allowedMethods.includes(req.method)) {
    res.setHeader('Allow', allowedMethods.join(', '));
    return res.status(405).json({ error: 'Method not allowed' });
  }
  next();
});

/**
 * JWKS endpoint - Serves public keys
 * GET /.well-known/jwks.json
 * Returns a JWKS containing only non-expired public keys
 */
app.get('/.well-known/jwks.json', (req, res) => {
  const currentTime = Math.floor(Date.now() / 1000);
  
  // Query for all non-expired keys
  db.all('SELECT kid, key, exp FROM keys WHERE exp > ?', [currentTime], (err, keys) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    // Convert private keys to public keys and then to JWK format
    const jwks = {
      keys: keys.map(key => {
        try {
          // Decrypt the private key
          const encryptedKey = JSON.parse(key.key);
          const decryptedKey = decryptData(encryptedKey);
          
          // Extract the public key from the private key
          const keyPair = crypto.createPrivateKey(decryptedKey);
          const publicKey = crypto.createPublicKey(keyPair).export({ format: 'pem', type: 'spki' });
          
          // Convert to JWK format and add required properties
          const jwk = pem2jwk(publicKey);
          jwk.kid = key.kid.toString();
          jwk.use = 'sig';
          jwk.alg = 'RS256';
          return jwk;
        } catch (error) {
          console.error('Error processing key:', error);
          return null;
        }
      }).filter(Boolean) // Remove any null entries
    };
    
    res.status(200).json(jwks);
  });
});

/**
 * Catch-all middleware for non-existent routes
 * Returns 404 Not Found for any undefined routes
 */
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

/**
 * Start the server on localhost:8080
 * The server only accepts connections from 127.0.0.1 for security
 */
const server = app.listen(8080, '127.0.0.1', () => {
  console.log('Enhanced JWKS server running on http://127.0.0.1:8080');
});

/**
 * Graceful shutdown function to close database connection when the server stops
 */
function shutdown() {
  console.log('Closing database connection and shutting down server...');
  db.close();
  server.close();
}

// Handle termination signals
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

module.exports = { app, server };