/*--------------------------------------------------------------------- //

Arnav Verma
CSCE 3550
11627633

I have used AI in my project mainly for documentation and adding comments in the code for better understanding 
//---------------------------------------------------------------------- */ 


/**
 * JWKS (JSON Web Key Set) Server Implementation
 * This server provides endpoints for JWT authentication and JWKS key management
 * with support for both valid and expired keys stored in SQLite database.
 */

const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { pem2jwk } = require('pem-jwk');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
app.use(express.json());

// Database setup
const dbPath = 'totally_not_my_privateKeys.db';
const db = new sqlite3.Database(dbPath);

/**
 * Initialize the database by creating the keys table if it doesn't exist
 * This follows the required schema from the project specification
 */
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS keys(
      kid INTEGER PRIMARY KEY AUTOINCREMENT,
      key BLOB NOT NULL,
      exp INTEGER NOT NULL
    )
  `);
});

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
 * Store a key in the database
 * @param {string} privateKey - Private key in PEM format
 * @param {number} expiry - Expiry timestamp
 * @returns {Promise} Promise that resolves with the key ID
 */
function storeKey(privateKey, expiry) {
  return new Promise((resolve, reject) => {
    const stmt = db.prepare('INSERT INTO keys (key, exp) VALUES (?, ?)');
    stmt.run(privateKey, expiry, function(err) {
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
 * POST /auth - Issues a JWT signed with a valid key
 * POST /auth?expired=true - Issues a JWT signed with an expired key
 * @returns {Object} JSON object containing the signed JWT
 */
app.post('/auth', (req, res) => {
  const useExpired = req.query.expired !== undefined;
  const currentTime = Math.floor(Date.now() / 1000);
  
  // Query for an appropriate key based on expiry
  let query;
  if (useExpired) {
    query = 'SELECT kid, key, exp FROM keys WHERE exp < ? ORDER BY kid DESC LIMIT 1';
  } else {
    query = 'SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid DESC LIMIT 1';
  }
  
  db.get(query, [currentTime], (err, key) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    if (!key) {
      return res.status(404).json({ error: 'Key not found' });
    }
    
    // Create JWT payload with subject and expiry
    const payload = {
      sub: 'user123',
      iat: Math.floor(Date.now() / 1000),
      exp: key.exp
    };

    // Sign the JWT using RS256 algorithm and include the key ID
    try {
      const token = jwt.sign(payload, key.key, {
        algorithm: 'RS256',
        header: { kid: key.kid.toString() }
      });
      
      res.status(200).json({ token });
    } catch (error) {
      console.error('JWT signing error:', error);
      res.status(500).json({ error: 'Error signing token' });
    }
  });
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
 * Each key in the set includes:
 * - Key ID (kid)
 * - Key use (use)
 * - Algorithm (alg)
 * - Key parameters (n, e)
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
        // Extract the public key from the private key
        const keyPair = crypto.createPrivateKey(key.key);
        const publicKey = crypto.createPublicKey(keyPair).export({ format: 'pem', type: 'spki' });
        
        // Convert to JWK format and add required properties
        const jwk = pem2jwk(publicKey);
        jwk.kid = key.kid.toString();
        jwk.use = 'sig';
        jwk.alg = 'RS256';
        return jwk;
      })
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
  console.log('JWKS server running on http://127.0.0.1:8080');
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