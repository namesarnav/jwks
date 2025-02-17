/*--------------------------------------------------------------------- //

Arnav Verma
CSCE 3550
11627633

I have used AI in my project mainly for documentation and adding comments in the code for better understanding 
//---------------------------------------------------------------------- */ 


/**
 * JWKS (JSON Web Key Set) Server Implementation
 * This server provides endpoints for JWT authentication and JWKS key management
 * with support for both valid and expired keys.
 */

const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { pem2jwk } = require('pem-jwk');

const app = express();
app.use(express.json());

/**
 * Generates an RSA key pair with specified key ID and expiry timestamp
 * @param {string} kid - Key identifier
 * @param {number} expiry - Expiry timestamp in seconds (Unix timestamp)
 * @returns {Object} Object containing key ID, public/private keys, and expiry
 */

function generateKeyPair(kid, expiry) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { kid, publicKey, privateKey, expiry };
}

// Calculate current time and expiry timestamps
const now = Math.floor(Date.now() / 1000);
const validExpiry = now + 3600;    // Valid for 1 hour from now
const expiredExpiry = now - 3600;  // Expired 1 hour ago

/**
 * Generate two keys:
 * 1. 'current' - A valid key that will expire in 1 hour
 * 2. 'expired' - A key that expired 1 hour ago
 */
const keys = [
  generateKeyPair('current', validExpiry),
  generateKeyPair('expired', expiredExpiry)
];

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
 * POST /auth - Issues a JWT signed with the current key
 * POST /auth?expired=true - Issues a JWT signed with the expired key
 * @returns {Object} JSON object containing the signed JWT
 */
app.post('/auth', (req, res) => {
  const useExpired = req.query.expired !== undefined;
  const key = keys.find(k => k.kid === (useExpired ? 'expired' : 'current'));
  
  if (!key) {
    return res.status(404).json({ error: 'Key not found' });
  }

  // Create JWT payload with subject and expiry
  const payload = {
    sub: 'user123',
    iat: Math.floor(Date.now() / 1000),
    exp: key.expiry
  };

  // Sign the JWT using RS256 algorithm and include the key ID
  const token = jwt.sign(payload, key.privateKey, {
    algorithm: 'RS256',
    header: { kid: key.kid }
  });

  res.status(200).json({ token });
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
  // Filter out expired keys
  const validKeys = keys.filter(key => key.expiry > currentTime);
  
  // Convert PEM keys to JWK format and add required properties
  const jwks = {
    keys: validKeys.map(key => {
      const jwk = pem2jwk(key.publicKey);
      jwk.kid = key.kid;
      jwk.use = 'sig';
      jwk.alg = 'RS256';
      return jwk;
    })
  };
  
  res.status(200).json(jwks);
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

module.exports = { app, server };