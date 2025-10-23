# 🔐 @sourceregistry/node-jwt
[![npm version](https://img.shields.io/npm/v/@sourceregistry/node-jwt?logo=npm)](https://www.npmjs.com/package/@sourceregistry/node-jwt)
[![License](https://img.shields.io/npm/l/@sourceregistry/node-jwt)](https://github.com/SourceRegistry/node-jwt/blob/main/LICENSE)
[![CI](https://github.com/SourceRegistry/node-jwt/actions/workflows/test.yml/badge.svg)](https://github.com/SourceRegistry/node-jwt/actions)
[![Codecov](https://img.shields.io/codecov/c/github/SourceRegistry/node-jwt)](https://codecov.io/gh/SourceRegistry/node-jwt)

A minimal, secure, and production-ready JWT (JSON Web Token) library for Node.js with zero dependencies. Supports all standard signing algorithms (HMAC, RSA, ECDSA, EdDSA, RSASSA-PSS) and full claim validation.

✨ **Why another JWT library?**  
Most JWT libraries are bloated, have security pitfalls, or lack proper TypeScript support. This library is:

- **Tiny**
- **Secure by default** (correct ECDSA/RSA/PSS/EdDSA encoding, time validation, algorithm whitelisting)
- **TypeScript-first** with full JSDoc
- **No external dependencies**
- **100% test coverage**
- **Dual API**: Sync and Promise-based

📦 **Installation**
```bash
npm install @sourceregistry/node-jwt
```
Requires Node.js ≥ 16

---

🚀 **Quick Start**

### Sync API (default)
```ts
import { sign, verify, decode } from '@sourceregistry/node-jwt';

// Sign
const token = sign(
  { sub: '1234567890', name: 'John Doe', iat: Math.floor(Date.now() / 1000) },
  'your-secret-key',
  { alg: 'HS256' }
);

// Verify
const result = verify(token, 'your-secret-key', { issuer: 'https://example.com' });
if (result.valid) {
  console.log('Payload:', result.payload);
} else {
  console.error('JWT Error:', result.error.code, result.error.reason);
}

// Decode (unsafe)
const { header, payload, signature } = decode(token);
```

### Promise API (`/promises`)
```ts
import { sign, verify, decode } from '@sourceregistry/node-jwt/promises';

// Sign
const token = await sign(
  { sub: '1234567890', name: 'John Doe', iat: Math.floor(Date.now() / 1000) },
  'your-secret-key',
  { alg: 'HS256' }
);

// Verify
try {
  const { payload, header, signature } = await verify(token, 'your-secret-key', {
    issuer: 'https://example.com',
    audience: 'my-app',
    algorithms: ['HS256']
  });
  console.log('Payload:', payload);
} catch (error) {
  console.error('JWT Error:', error.code, error.reason);
}

// Decode (unsafe)
const { header, payload, signature } = await decode(token);
```

---

🔑 **Supported Algorithms**

| Algorithm   | Type         | Secret Type                              |
|-------------|--------------|------------------------------------------|
| HS256       | HMAC         | `string \| Buffer`                       |
| HS384       | HMAC         | `string \| Buffer`                       |
| HS512       | HMAC         | `string \| Buffer`                       |
| RS256       | RSA          | Private key (sign), Public key (verify)  |
| RS384       | RSA          | Private key (sign), Public key (verify)  |
| RS512       | RSA          | Private key (sign), Public key (verify)  |
| PS256       | RSA-PSS      | Private key (sign), Public key (verify)  |
| PS384       | RSA-PSS      | Private key (sign), Public key (verify)  |
| PS512       | RSA-PSS      | Private key (sign), Public key (verify)  |
| ES256       | ECDSA        | Private key (sign), Public key (verify)  |
| ES384       | ECDSA        | Private key (sign), Public key (verify)  |
| ES512       | ECDSA        | Private key (sign), Public key (verify)  |
| ES256K      | ECDSA (secp256k1) | Private key (sign), Public key (verify) |
| EdDSA       | Ed25519      | Private key (sign), Public key (verify)  |

> 💡 Keys must be in PEM format or as Node.js `KeyObject` (e.g., from `crypto.generateKeyPairSync`).

---

🛡️ **Security Features**

✅ Correct ECDSA signatures (DER-encoded, not IEEE P1363)  
✅ Full RSASSA-PSS and Ed25519 support  
✅ Strict algorithm validation with **whitelist** (`algorithms` option) to prevent algorithm confusion  
✅ Time claim validation (`exp`, `nbf`, `iat`) with **clock skew** tolerance  
✅ Optional validation for:  
 • Issuer (`iss`)  
 • Subject (`sub`)  
 • Audience (`aud`)  
 • JWT ID (`jti`)  
✅ Maximum token age enforcement (`maxTokenAge`)  
✅ Type header enforcement (`typ: 'JWT'`)  
✅ Timing-safe signature comparison  
✅ No unsafe defaults

---

📚 **API Reference**

### Sync vs Promise API

| Operation | Sync Return | Promise Behavior |
|----------|-------------|------------------|
| `sign()` | `string` | Resolves to `string` |
| `decode()` | `{ header, payload, signature }` | Resolves to same object |
| `verify()` | `{ valid: true, ... } \| { valid: false, error }` | **Resolves** on success<br>**Rejects** with `{ reason, code }` on failure |

---

### `sign(payload, secret, options?)`
Sign a JWT.

- `payload`: `JWTPayload` object
- `secret`: Key for signing (type depends on algorithm)
- `options`:
    - `alg`: Algorithm (default: `'HS256'`)
    - `kid`: Key ID
    - `typ`: Token type (default: `'JWT'`)

Returns: `string` (JWT)

---

### `verify(token, secret, options?)`
Verify and validate a JWT.

- `token`: JWT string
- `secret`: Key for verification
- `options`:
    - `algorithms`: Array of allowed algorithms (e.g., `['HS256', 'RS256']`)
    - `issuer`: Required value for the `iss` claim
    - `subject`: Required value for the `sub` claim
    - `audience`: Required value(s) for the `aud` claim (`string` or `string[]`)
    - `jwtId`: Required value for the `jti` claim
    - `ignoreExpiration`: Skip `exp` check (default: `false`)
    - `clockSkew`: Tolerance in seconds for time validation (default: `0`)
    - `maxTokenAge`: Maximum allowed token age in seconds (from `iat`)

#### Sync Usage:
```ts
const result = verify(token, secret, { issuer: 'https://example.com' });
if (result.valid) {
  // success
} else {
  // handle error: result.error
}
```

#### Promise Usage:
```ts
try {
  const { header, payload, signature } = await verify(token, secret, { issuer: 'https://example.com' });
  // success
} catch (error) {
  // handle error: error.reason, error.code
}
```

#### Error Codes:
- `INVALID_TOKEN`: Malformed token structure
- `INVALID_ALGORITHM`: Unsupported algorithm
- `ALGORITHM_NOT_ALLOWED`: Algorithm not in allowed list
- `INVALID_TYPE`: Invalid `typ` header
- `INVALID_SIGNATURE`: Signature mismatch
- `TOKEN_EXPIRED`: `exp` claim exceeded
- `TOKEN_NOT_ACTIVE`: `nbf` claim not reached
- `TOKEN_FUTURE_ISSUED`: `iat` claim in future
- `TOKEN_TOO_OLD`: Token age exceeds `maxTokenAge`
- `MISSING_ISSUER` / `INVALID_ISSUER`
- `MISSING_SUBJECT` / `INVALID_SUBJECT`
- `MISSING_AUDIENCE` / `INVALID_AUDIENCE`
- `MISSING_JTI` / `INVALID_JTI`

---

### `decode(token)`
Decode a JWT without verification (**use with caution!**).

- `token`: JWT string
- Returns: `{ header, payload, signature }`
- Throws on malformed tokens (sync) / Rejects (promise)

---

🧪 **Testing**
This library has 100% test coverage with Vitest:
```bash
npm test
npm run test:coverage
```

Tests include:
- All algorithms (HMAC, RSA, ECDSA, EdDSA, PSS)
- Time validation (`exp`, `nbf`, `iat`, `clockSkew`, `maxTokenAge`)
- Claim validation (`iss`, `sub`, `aud`, `jti`)
- Algorithm whitelisting
- Malformed token handling
- Signature verification (including timing-safe comparison)
- Custom claims
- Both sync and promise APIs

---

📦 **Exports**
This package provides two entrypoints:

| Import | Description |
|--------|-------------|
| `@sourceregistry/node-jwt` | Sync API (default) |
| `@sourceregistry/node-jwt/promises` | Promise-based API |

Both include full TypeScript types and JSDoc.

---

🙌 **Contributing**
PRs welcome! Please:
- Add tests for new features
- Maintain 100% coverage
- Follow existing code style

Found a security issue? [Report it responsibly](mailto:a.p.a.slaa@projectsource.nl).

🔗 **GitHub**: [github.com/SourceRegistry/node-jwt](https://github.com/SourceRegistry/node-jwt)  
📦 **npm**: [@sourceregistry/node-jwt](https://www.npmjs.com/package/@sourceregistry/node-jwt)
