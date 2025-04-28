const request = require('supertest');
const jwt = require('jsonwebtoken');
const assert = require('assert');
const { app, server } = require('./server');
const sqlite3 = require('sqlite3').verbose();
const sinon = require('sinon');
const crypto = require('crypto');

describe('Enhanced JWKS Server with SQLite', () => {
  let db;
  let sandbox;

  before((done) => {
    // Connect to the database for testing
    db = new sqlite3.Database('totally_not_my_privateKeys.db', (err) => {
      if (err) {
        return done(err);
      }
      // Ensure we have test data
      setTimeout(done, 500); // Give a moment for keys to be initialized
    });
    sandbox = sinon.createSandbox();
  });

  after((done) => {
    // Close database connection after tests
    if (db) {
      db.close(done);
    } else {
      done();
    }
    sandbox.restore();
  });

  describe('Database setup', () => {
    it('should have created the keys table', (done) => {
      db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='keys'", (err, row) => {
        if (err) return done(err);
        assert.ok(row, 'Keys table should exist');
        done();
      });
    });
    
    it('should have created the users table', (done) => {
      db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='users'", (err, row) => {
        if (err) return done(err);
        assert.ok(row, 'Users table should exist');
        done();
      });
    });
    
    it('should have created the auth_logs table', (done) => {
      db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='auth_logs'", (err, row) => {
        if (err) return done(err);
        assert.ok(row, 'Auth logs table should exist');
        done();
      });
    });

    it('should have populated keys in the database', (done) => {
      db.all('SELECT * FROM keys', (err, rows) => {
        if (err) return done(err);
        assert.ok(rows.length >= 2, 'Database should have at least 2 keys');
        done();
      });
    });
  });

  describe('Utility Functions', () => {
    it('should encrypt and decrypt data correctly', () => {
      const serverModule = require('./server');
      const text = 'test private key';
      const encrypted = serverModule.encryptData(text);
      assert.ok(encrypted.iv, 'Should have initialization vector');
      assert.ok(encrypted.encryptedData, 'Should have encrypted data');
      assert.ok(encrypted.authTag, 'Should have auth tag');
      const decrypted = serverModule.decryptData(encrypted);
      assert.strictEqual(decrypted, text, 'Decrypted text should match original');
    });

    it('should generate valid RSA key pair', () => {
      const serverModule = require('./server');
      const expiry = Math.floor(Date.now() / 1000) + 3600;
      const keyPair = serverModule.generateKeyPair(expiry);
      assert.ok(keyPair.publicKey.includes('BEGIN PUBLIC KEY'), 'Should generate valid public key');
      assert.ok(keyPair.privateKey.includes('BEGIN PRIVATE KEY'), 'Should generate valid private key');
      assert.strictEqual(keyPair.expiry, expiry, 'Expiry should match input');
    });

    it('should store and retrieve key correctly', (done) => {
      const serverModule = require('./server');
      const privateKey = '-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----';
      const expiry = Math.floor(Date.now() / 1000) + 3600;
      serverModule.storeKey(privateKey, expiry).then((kid) => {
        serverModule.getKey(kid).then((retrievedKey) => {
          assert.strictEqual(retrievedKey, privateKey, 'Retrieved key should match stored key');
          done();
        }).catch(done);
      }).catch(done);
    });

    it('should handle decryption failure', () => {
      const serverModule = require('./server');
      const invalidEncryptedData = {
        iv: 'invalid_iv',
        encryptedData: 'invalid_data',
        authTag: 'invalid_tag'
      };
      assert.throws(() => serverModule.decryptData(invalidEncryptedData), /Invalid/, 'Should throw on invalid decryption');
    });
  });

  describe('GET /.well-known/jwks.json', () => {
    it('should return only non-expired keys', (done) => {
      request(app)
        .get('/.well-known/jwks.json')
        .expect('Content-Type', /json/)
        .expect(200)
        .end((err, response) => {
          if (err) return done(err);
          
          const jwks = response.body;
          assert.ok(jwks.keys.length > 0, 'Should return at least one key');
          
          jwks.keys.forEach(key => {
            assert.ok(key.kid, 'Key should have a kid');
            assert.strictEqual(key.use, 'sig');
            assert.strictEqual(key.alg, 'RS256');
            assert.ok(key.n, 'Key should have modulus');
            assert.ok(key.e, 'Key should have exponent');
          });
          
          done();
        });
    });

    it('should handle database errors', (done) => {
      sinon.stub(db, 'all').callsArgWith(2, new Error('Database error'));
      request(app)
        .get('/.well-known/jwks.json')
        .expect(500)
        .end((err, res) => {
          if (err) return done(err);
          assert.strictEqual(res.body.error, 'Internal server error');
          db.all.restore();
          done();
        });
    });
  });

  describe('POST /auth', () => {
    it('should return a valid JWT signed with a non-expired key', (done) => {
      request(app)
        .post('/auth')
        .expect('Content-Type', /json/)
        .expect(200)
        .end((err, response) => {
          if (err) return done(err);
          
          const token = response.body.token;
          assert.ok(token, 'Response should include a token');
          
          const decoded = jwt.decode(token, { complete: true });
          assert.ok(decoded, 'Token should be decodable');
          assert.ok(decoded.header.kid, 'Token should have a key ID');
          assert.ok(decoded.payload.exp > Math.floor(Date.now() / 1000), 
            'Token should have a future expiry time');
            
          done();
        });
    });

    it('should return a JWT signed with an expired key when requested', (done) => {
      request(app)
        .post('/auth?expired=true')
        .expect('Content-Type', /json/)
        .expect(200)
        .end((err, response) => {
          if (err) return done(err);
          
          const token = response.body.token;
          assert.ok(token, 'Response should include a token');
          
          const decoded = jwt.decode(token, { complete: true });
          assert.ok(decoded, 'Token should be decodable');
          assert.ok(decoded.header.kid, 'Token should have a key ID');
          assert.ok(decoded.payload.exp < Math.floor(Date.now() / 1000), 
            'Token should have a past expiry time');
            
          done();
        });
    });

    it('should return 404 when no key is found', (done) => {
      sinon.stub(db, 'get').callsArgWith(2, null, null);
      request(app)
        .post('/auth')
        .expect(404)
        .end((err, res) => {
          if (err) return done(err);
          assert.strictEqual(res.body.error, 'Key not found');
          db.get.restore();
          done();
        });
    });

    it('should handle database errors', (done) => {
      sinon.stub(db, 'get').callsArgWith(2, new Error('Database error'));
      request(app)
        .post('/auth')
        .expect(500)
        .end((err, res) => {
          if (err) return done(err);
          assert.strictEqual(res.body.error, 'Internal server error');
          db.get.restore();
          done();
        });
    });

    it('should handle JWT signing errors', (done) => {
      sinon.stub(crypto, 'createDecipheriv').throws(new Error('Decryption error'));
      request(app)
        .post('/auth')
        .expect(500)
        .end((err, res) => {
          if (err) return done(err);
          assert.strictEqual(res.body.error, 'Error signing token');
          crypto.createDecipheriv.restore();
          done();
        });
    });
    
    it('should log authentication requests', (done) => {
      request(app)
        .post('/auth')
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);
          
          db.get('SELECT COUNT(*) as count FROM auth_logs', (err, row) => {
            if (err) return done(err);
            assert.ok(row.count > 0, 'Should have authentication logs');
            done();
          });
        });
    });
    
    it('should respect rate limits', function(done) {
      this.timeout(5000);
      
      const requests = [];
      for (let i = 0; i < 11; i++) {
        requests.push(request(app).post('/auth'));
      }
      
      Promise.all(requests.map(r => r.catch(e => e)))
        .then(responses => {
          const rateLimited = responses.some(res => res.status === 429);
          assert.ok(rateLimited, 'Should have rate limited at least one request');
          const rateLimitedResponse = responses.find(res => res.status === 429);
          assert.strictEqual(rateLimitedResponse.body.error, 'Too many requests');
          assert.ok(rateLimitedResponse.headers['rate-limit'], 'Should include rate limit headers');
          done();
        })
        .catch(done);
    });
  });

  describe('POST /register', () => {
    it('should register a new user and return a password', (done) => {
      const username = `test_user_${Date.now()}`;
      request(app)
        .post('/register')
        .send({ username, email: `${username}@example.com` })
        .expect('Content-Type', /json/)
        .expect(201)
        .end((err, response) => {
          if (err) return done(err);
          
          assert.ok(response.body.password, 'Should return a generated password');
          
          db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
            if (err) return done(err);
            assert.ok(row, 'User should exist in database');
            assert.strictEqual(row.username, username);
            assert.ok(row.password_hash.startsWith('$argon2'), 'Password should be hashed with Argon2');
            done();
          });
        });
    });
    
    it('should reject duplicate usernames', (done) => {
      const username = `test_user_${Date.now()}`;
      
      request(app)
        .post('/register')
        .send({ username, email: `${username}@example.com` })
        .expect(201)
        .end((err) => {
          if (err) return done(err);
          
          request(app)
            .post('/register')
            .send({ username, email: `${username}2@example.com` })
            .expect(409)
            .end((err, res) => {
              if (err) return done(err);
              assert.strictEqual(res.body.error, 'Username already exists');
              done();
            });
        });
    });

    it('should reject missing username or email', (done) => {
      request(app)
        .post('/register')
        .send({ email: 'test@example.com' })
        .expect(400)
        .end((err, res) => {
          if (err) return done(err);
          assert.strictEqual(res.body.error, 'Username and email are required');
          done();
        });
    });
  });

  describe('HTTP method handling', () => {
    it('should reject non-allowed methods for /auth endpoint', (done) => {
      request(app)
        .get('/auth')
        .expect(405)
        .end((err, res) => {
          if (err) return done(err);
          assert.strictEqual(res.body.error, 'Method not allowed');
          assert.ok(res.headers.allow.includes('POST'));
          done();
        });
    });

    it('should reject non-allowed methods for JWKS endpoint', (done) => {
      request(app)
        .post('/.well-known/jwks.json')
        .expect(405)
        .end((err, res) => {
          if (err) return done(err);
          assert.strictEqual(res.body.error, 'Method not allowed');
          assert.ok(res.headers.allow.includes('GET'));
          done();
        });
    });

    it('should handle CORS preflight requests', (done) => {
      request(app)
        .options('/auth')
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);
          assert.strictEqual(res.status, 200, 'Should return 200 for OPTIONS request');
          done();
        });
    });

    it('should return 404 for unknown routes', (done) => {
      request(app)
        .get('/unknown')
        .expect(404)
        .end((err, res) => {
          if (err) return done(err);
          assert.strictEqual(res.body.error, 'Not found');
          done();
        });
    });
  });

  describe('SQL injection protection', () => {
    it('should safely handle malicious input in query parameters', (done) => {
      request(app)
        .post('/auth?expired=1%27%20OR%20%271%27=%271')
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);
          assert.ok(res.body.token, 'Should return a token even with malicious input');
          done();
        });
    });
    
    it('should safely handle malicious input in registration', (done) => {
      const maliciousUsername = "user'; DROP TABLE users; --";
      request(app)
        .post('/register')
        .send({ username: maliciousUsername, email: 'test@example.com' })
        .end((err) => {
          if (err) return done(err);
          
          db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='users'", (err, row) => {
            if (err) return done(err);
            assert.ok(row, 'Users table should still exist after SQL injection attempt');
            done();
          });
        });
    });
  });

  describe('Server shutdown', () => {
    it('should handle SIGINT gracefully', (done) => {
      const dbCloseSpy = sinon.spy(db, 'close');
      const serverCloseSpy = sinon.spy(server, 'close');
      process.emit('SIGINT');
      setTimeout(() => {
        assert.ok(dbCloseSpy.called, 'Database close should be called');
        assert.ok(serverCloseSpy.called, 'Server close should be called');
        dbCloseSpy.restore();
        serverCloseSpy.restore();
        done();
      }, 100);
    });

    it('should handle SIGTERM gracefully', (done) => {
      const dbCloseSpy = sinon.spy(db, 'close');
      const serverCloseSpy = sinon.spy(server, 'close');
      process.emit('SIGTERM');
      setTimeout(() => {
        assert.ok(dbCloseSpy.called, 'Database close should be called');
        assert.ok(serverCloseSpy.called, 'Server close should be called');
        dbCloseSpy.restore();
        serverCloseSpy.restore();
        done();
      }, 100);
    });
  });
});