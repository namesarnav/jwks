const request = require('supertest');
const jwt = require('jsonwebtoken');
const assert = require('assert');
const { app } = require('./server');

describe('JWKS Server', () => {
  describe('GET /jwks', () => {
    it('should return only non-expired keys', (done) => {
      request(app)
        .get('/.well-known/jwks.json')
        .expect('Content-Type', /json/)
        .expect(200)
        .end((err, response) => {
          if (err) return done(err);
          const jwks = response.body;
          assert.strictEqual(jwks.keys.length, 1);
          assert.strictEqual(jwks.keys[0].kid, 'current');
          assert.strictEqual(jwks.keys[0].use, 'sig');
          assert.strictEqual(jwks.keys[0].alg, 'RS256');
          done();
        });
    });

    it('should not include expired keys', (done) => {
      request(app)
        .get('/.well-known/jwks.json')
        .expect(200)
        .end((err, response) => {
          if (err) return done(err);
          const expiredKey = response.body.keys.find(k => k.kid === 'expired');
          assert.strictEqual(expiredKey, undefined);
          done();
        });
    });
  });

  describe('POST /auth', () => {
    it('should return a valid JWT signed with the current key', (done) => {
      request(app)
        .post('/auth')
        .expect('Content-Type', /json/)
        .expect(200)
        .end((err, response) => {
          if (err) return done(err);
          const token = response.body.token;
          assert.ok(token);
          
          const decoded = jwt.decode(token, { complete: true });
          assert.strictEqual(decoded.header.kid, 'current');
          assert.ok(decoded.payload.exp > Math.floor(Date.now() / 1000));
          done();
        });
    });

    it('should return a JWT signed with expired key when requested', (done) => {
      request(app)
        .post('/auth?expired=true')
        .expect('Content-Type', /json/)
        .expect(200)
        .end((err, response) => {
          if (err) return done(err);
          const token = response.body.token;
          assert.ok(token);
          
          const decoded = jwt.decode(token, { complete: true });
          assert.strictEqual(decoded.header.kid, 'expired');
          assert.ok(decoded.payload.exp < Math.floor(Date.now() / 1000));
          done();
        });
    });
  });
});