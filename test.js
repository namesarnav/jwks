const request = require('supertest');
const jwt = require('jsonwebtoken');
const assert = require('assert');
const { app } = require('./server');
const sqlite3 = require('sqlite3').verbose();

describe('Enhanced JWKS Server with SQLite', () => {
  let db;

  before((done) => {
    // Connect to the database for testing
    db = new sqlite3.Database('totally_not_my_privateKeys.db', (err) => {
      if (err) {
        return done(err);
      }
      // Ensure we have test data
      setTimeout(done, 500); // Give a moment for keys to be initialized
    });
  });

  after((done) => {
    // Close database connection after tests
    if (db) {
      db.close(done);
    } else {
      done();
    }
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
          
          // Confirm keys have required properties
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
    
    it('should log authentication requests', (done) => {
      request(app)
        .post('/auth')
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);
          
          // Check if the log was created
          db.get('SELECT COUNT(*) as count FROM auth_logs', (err, row) => {
            if (err) return done(err);
            assert.ok(row.count > 0, 'Should have authentication logs');
            done();
          });
        });
    });
    
    it('should respect rate limits', function(done) {
      this.timeout(5000);
      
      // Send 11 requests (1 more than the limit)
      const requests = [];
      for (let i = 0; i < 11; i++) {
        requests.push(request(app).post('/auth'));
      }
      
      // Execute all requests as fast as possible
      Promise.all(requests.map(r => r.catch(e => e)))
        .then(responses => {
          // Check if at least one request was rate limited
          const rateLimited = responses.some(res => res.status === 429);
          assert.ok(rateLimited, 'Should have rate limited at least one request');
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
          
          // Verify the user was created in the database
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
      
      // First registration
      request(app)
        .post('/register')
        .send({ username, email: `${username}@example.com` })
        .expect(201)
        .end((err) => {
          if (err) return done(err);
          
          // Try to register with the same username
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
  });

  describe('SQL injection protection', () => {
    it('should safely handle malicious input in query parameters', (done) => {
      request(app)
        .post('/auth?expired=1%27%20OR%20%271%27=%271') // Trying SQL injection: ?expired=1' OR '1'='1
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
          
          // Verify the users table still exists
          db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='users'", (err, row) => {
            if (err) return done(err);
            assert.ok(row, 'Users table should still exist after SQL injection attempt');
            done();
          });
        });
    });
  });
});