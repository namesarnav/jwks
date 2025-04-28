# JWKS Server Implementation with SQLite

A secure implementation of a JSON Web Key Set (JWKS) server that manages cryptographic keys for JWT authentication. This server provides endpoints for JWT generation and public key distribution, with persistent storage using SQLite database.

## Features

- JWKS endpoint serving public keys
- JWT authentication endpoint
- Support for both valid and expired keys
- SQLite database for persistent key storage
- AES-256 encryption of private keys
- User registration and authentication
- Authentication request logging
- Rate limiting protection
- Parameterized SQL queries for injection protection
- Proper HTTP method handling
- RSA key pair generation
- Secure error handling
- Argon2 password hashing

## Prerequisites

- Node.js (v14 or higher)
- npm (Node Package Manager)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd jwks-server
```

2. Install dependencies:
```bash
npm install
```

3. Set environment variables:
```bash
# Optional: Set a custom encryption key (32 bytes)
export HOT_KEY=your_32_character_aes_encryption_key
```

## Required Dependencies

```json
{
  "dependencies": {
    "argon2": "^0.43.0",
    "express": "^4.18.2",
    "express-rate-limit": "^7.5.0",
    "jsonwebtoken": "^9.0.2",
    "pem-jwk": "^2.0.0",
    "sqlite3": "^5.1.7"
  },
  "devDependencies": {
    "mocha": "^10.8.2",
    "nyc": "^15.1.0",
    "supertest": "^6.3.4"
  }
}
```

## Usage

### Starting the Server

```bash
node server.js
```

The server will start on `http://127.0.0.1:8080` and create the SQLite database file `totally_not_my_privateKeys.db` if it doesn't exist.

### Endpoints

#### 1. JWKS Endpoint

- **URL**: `/.well-known/jwks.json`
- **Method**: `GET`
- **Response**: JSON Web Key Set containing non-expired public keys
```json
{
  "keys": [
    {
      "kid": "1",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "..."
    }
  ]
}
```

#### 2. JWT Authentication Endpoint

- **URL**: `/auth`
- **Method**: `POST`
- **Query Parameters**: 
  - `expired` (optional): When present, returns a token signed with an expired key
- **Response**: JWT token
```json
{
  "token": "eyJhbGciOiJSUzI1..."
}
```

#### 3. User Registration Endpoint

- **URL**: `/register`
- **Method**: `POST`
- **Request Body**:
```json
{
  "username": "myUsername",
  "email": "user@example.com",
  "password": "securePassword123!"
}
```
- **Response**: Returns the user password with status 201
```json
{
  "password": "securePassword123!"
}
```

#### 4. User Authentication Endpoint

- **URL**: `/auth`
- **Method**: `POST`
- **Request Body**:
```json
{
  "username": "myUsername",
  "password": "securePassword123!"
}
```
- **Response**: Returns a JWT token for the authenticated user
```json
{
  "token": "eyJhbGciOiJSUzI1..."
}
```

## Testing

Run the test suite:
```bash
npm test
```

Generate test coverage report:
```bash
npm run coverage
```

The tests verify:
- Database creation and schema
- JWKS endpoint returns only valid keys
- Expired keys are properly filtered
- JWT generation with both valid and expired keys
- User registration and authentication
- Authentication logging
- Rate limiting protection
- AES encryption of keys
- Proper HTTP method handling
- SQL injection protection

## Implementation Details

### Database Schema

```sql
-- Keys table for JWT signing keys
CREATE TABLE IF NOT EXISTS keys(
  kid INTEGER PRIMARY KEY AUTOINCREMENT,
  key BLOB NOT NULL,
  exp INTEGER NOT NULL
)

-- Users table for registration and authentication
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  email TEXT NOT NULL,
  date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP
)

-- Auth logs table for authentication request tracking
CREATE TABLE IF NOT EXISTS auth_logs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_ip TEXT NOT NULL,
  request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  user_id INTEGER,
  FOREIGN KEY(user_id) REFERENCES users(id)
)
```

### Key Management

- Generates RSA key pairs with 2048-bit keys
- Encrypts private keys with AES-256-CBC before storage
- Stores encrypted private keys in the database
- Uses environment variable `HOT_KEY` for the encryption key
- Maintains two types of keys:
  - Current key (valid for 1 hour)
  - Expired key (expired 1 hour ago)

### Security Features

- AES-256 encryption for private keys
- Argon2 password hashing for user credentials
- Rate limiting to prevent brute force attacks
- Authentication request logging for audit trails
- Uses RS256 algorithm for JWT signing
- Parameterized SQL queries to prevent injection
- Proper error handling and status codes
- Input validation
- HTTP method restrictions
- Database connection security

### Rate Limiting

The server implements rate limiting for authentication endpoints:
- 10 requests per second maximum
- Returns 429 status code when limit is exceeded
- Helps prevent brute force attacks

### Authentication Logging

All authentication requests are logged to the database:
- Records client IP address
- Timestamps each request
- Tracks user ID when authenticated
- Provides audit trail for security analysis

## Error Handling

The server returns appropriate HTTP status codes:
- 200: Successful request
- 201: Resource created successfully
- 400: Bad request (missing fields)
- 401: Unauthorized (invalid credentials)
- 404: Resource not found
- 405: Method not allowed
- 409: Conflict (e.g., username already exists)
- 429: Too many requests (rate limit exceeded)
- 500: Internal server error

## Blackbox Testing

The server is compatible with the provided blackbox testing tool:
```bash
gradebot.exe project2
```

This will validate:
- JWT authentication
- Valid JWK found in JWKS
- SQLite database usage
- Proper database queries
- AES encryption of private keys
- User registration functionality
- Authentication logging
- Rate limiting implementation

## Contributing

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -am 'Add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Authors

- Arnav Verma

## Acknowledgments

- Express.js team
- jsonwebtoken maintainers
- pem-jwk contributors
- SQLite developers
- Argon2 implementation team
- Express Rate Limit contributors

## Use of AI

In this project, I utilized Claude, an AI assistant by Anthropic, to:
- Generate comprehensive documentation and comments in the code
- Create a detailed README.md file
- Enhance code readability through proper documentation
- Structure the project documentation in a professional manner
- Assist with SQLite database integration
- Implement security features like AES encryption and rate limiting

The core implementation and logic were written by me, while AI was used as a tool to improve documentation, code clarity, and security implementations. This acknowledgment is in line with best practices for AI usage transparency in software development.