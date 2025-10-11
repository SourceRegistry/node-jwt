# 🔐 node-jwt

[![npm version](https://img.shields.io/npm/v/@sourceregistry/node-jwt?logo=npm)](https://www.npmjs.com/package/@sourceregistry/node-jwt)
[![License](https://img.shields.io/npm/l/@sourceregistry/node-jwt)](LICENSE)
[![Tests](https://github.com/SourceRegistry/node-jwt/actions/workflows/test.yml/badge.svg)](https://github.com/SourceRegistry/node-jwt/actions)
[![Coverage](https://img.shields.io/codecov/c/github/SourceRegistry/node-jwt)](https://codecov.io/gh/SourceRegistry/node-jwt)

A **minimal**, **secure**, and **production-ready** JWT (JSON Web Token) library for Node.js with **zero dependencies**. Supports all standard signing algorithms (HMAC, RSA, ECDSA) and full claim validation.

> ✨ **Why another JWT library?**  
> Most JWT libraries are bloated, have security pitfalls, or lack proper TypeScript support. This library is:
> - **Tiny**
> - **Secure by default** (correct ECDSA/RSA encoding, time validation)
> - **TypeScript-first** with full JSDoc
> - **No external dependencies**
> - **100% test coverage**

---

## 📦 Installation

```bash
npm install @sourceregistry/node-jwt
```

> **Requires Node.js ≥ 16**

---

## 🚀 Quick Start

### Sign a token
```ts
import { sign } from '@sourceregistry/node-jwt';

const token = sign(
  { sub: '1234567890', name: 'John Doe', iat: Math.floor(Date.now() / 1000) },
  'your-secret-key',
  { alg: 'HS256' }
);
```

### Verify a token
```ts
import { verify } from '@sourceregistry/node-jwt';

const result = verify(token, 'your-secret-key');

if (result.valid) {
  console.log('Payload:', result.payload);
} else {
  console.error('JWT Error:', result.error.code, result.error.reason);
}
```

### Decode (unsafe — no verification)
```ts
import { decode } from '@sourceregistry/node-jwt';

const { header, payload, signature } = decode(token);
```

---

## 🔑 Supported Algorithms

| Algorithm | Type    | Secret Type                     |
|-----------|---------|---------------------------------|
| `HS256`   | HMAC    | `string \| Buffer`              |
| `HS384`   | HMAC    | `string \| Buffer`              |
| `HS512`   | HMAC    | `string \| Buffer`              |
| `RS256`   | RSA     | Private key (signing)<br>Public key (verifying) |
| `RS384`   | RSA     | Private key (signing)<br>Public key (verifying) |
| `RS512`   | RSA     | Private key (signing)<br>Public key (verifying) |
| `ES256`   | ECDSA   | Private key (signing)<br>Public key (verifying) |
| `ES384`   | ECDSA   | Private key (signing)<br>Public key (verifying) |
| `ES512`   | ECDSA   | Private key (signing)<br>Public key (verifying) |

> 💡 **Note**: RSA/ECDSA keys must be in **PEM format** or as Node.js `KeyObject`.

---

## 🛡️ Security Features

- ✅ **Correct ECDSA signatures** (DER-encoded, not IEEE P1363)
- ✅ **Strict algorithm validation** (prevents algorithm confusion attacks)
- ✅ **Time claim validation** (`exp`, `nbf`, `iat`) with **clock skew tolerance**
- ✅ **Type header enforcement** (`typ: 'JWT'`)
- ✅ **No unsafe defaults**

---

## 📚 API Reference

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
    - `ignoreExpiration`: Skip `exp` check (default: `false`)
    - `clockSkew`: Tolerance in seconds for time validation (default: `0`)

Returns:
```ts
| { valid: true; header: JWTHeader; payload: JWTPayload; signature: string }
| { valid: false; error: { reason: string; code: string } }
```

**Error Codes**:
- `INVALID_TOKEN`: Malformed token structure
- `INVALID_ALGORITHM`: Unsupported algorithm
- `INVALID_TYPE`: Invalid `typ` header
- `INVALID_SIGNATURE`: Signature mismatch
- `TOKEN_EXPIRED`: `exp` claim exceeded
- `TOKEN_NOT_ACTIVE`: `nbf` claim not reached
- `TOKEN_FUTURE_ISSUED`: `iat` claim in future

---

### `decode(token)`
Decode a JWT without verification (use with caution!).

- `token`: JWT string

Returns: `{ header, payload, signature }`

Throws on malformed tokens.

---

## 🧪 Testing

This library has **100% test coverage** with Vitest:

```bash
npm test
npm run test:coverage
```

Tests include:
- All algorithms (HMAC, RSA, ECDSA)
- Time validation edge cases
- Malformed token handling
- Signature verification
- Custom claims

---

## 🙌 Contributing

PRs welcome! Please:
1. Add tests for new features
2. Maintain 100% coverage
3. Follow existing code style

Found a security issue? [Report it responsibly](mailto:a.p.a.slaa@projectsource.nl).
