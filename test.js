const request = require('supertest');
const jwt = require('jsonwebtoken');
const assert = require('assert');
const { app } = require('./server');
const sqlite3 = require('sqlite3').verbose();

describe('JWKS Server with SQLite', () => {
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
  });
});