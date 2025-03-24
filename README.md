# JWKS Server Implementation

A secure implementation of a JSON Web Key Set (JWKS) server that manages cryptographic keys for JWT authentication. This server provides endpoints for JWT generation and public key distribution, supporting both valid and expired keys.

## Features

- JWKS endpoint serving public keys
- JWT authentication endpoint
- Support for both valid and expired keys
- Proper HTTP method handling
- RSA key pair generation
- Secure error handling

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

## Required Dependencies

```json
{
  "dependencies": {
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0",
    "pem-jwk": "^2.0.0"
  },
  "devDependencies": {
    "mocha": "^10.2.0",
    "supertest": "^6.3.3"
  }
}
```

## Usage

### Starting the Server

```bash
node server.js
```

The server will start on `http://127.0.0.1:8080`.

### Endpoints

#### 1. JWKS Endpoint
- **URL**: `/.well-known/jwks.json`
- **Method**: `GET`
- **Response**: JSON Web Key Set containing non-expired public keys
```json
{
  "keys": [
    {
      "kid": "current",
      "use": "sig",
      "alg": "RS256",
      "...": "..."
    }
  ]
}
```

#### 2. Authentication Endpoint
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

## Testing

Run the test suite:
```bash
npm test
```

The tests verify:
- JWKS endpoint returns only valid keys
- Expired keys are properly filtered
- JWT generation with both valid and expired keys
- Proper HTTP method handling

## Implementation Details

### Key Management
- Generates RSA key pairs with 2048-bit keys
- Maintains two keys:
  - Current key (valid for 1 hour)
  - Expired key (expired 1 hour ago)

### Security Features
- Uses RS256 algorithm for JWT signing
- Proper error handling and status codes
- Input validation
- HTTP method restrictions

## Error Handling

The server returns appropriate HTTP status codes:
- 200: Successful request
- 404: Resource not found
- 405: Method not allowed

## Contributing

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -am 'Add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Authors

- Arnav

## Acknowledgments

- Express.js team
- jsonwebtoken maintainers
- pem-jwk contributors

## Use of AI

In this project, I utilized Claude, an AI assistant by Anthropic, to:
- Generate comprehensive documentation and comments in the code
- Create a detailed README.md file
- Enhance code readability through proper documentation
- Structure the project documentation in a professional manner

The core implementation and logic were written by me, while AI was used as a tool to improve documentation and code clarity. This acknowledgment is in line with best practices for AI usage transparency in software development.
