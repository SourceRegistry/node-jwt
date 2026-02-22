# 🔐 @sourceregistry/node-jwt

[![npm version](https://img.shields.io/npm/v/@sourceregistry/node-jwt?logo=npm)](https://www.npmjs.com/package/@sourceregistry/node-jwt)
[![License](https://img.shields.io/npm/l/@sourceregistry/node-jwt)](https://github.com/SourceRegistry/node-jwt/blob/main/LICENSE)
[![CI](https://github.com/SourceRegistry/node-jwt/actions/workflows/test.yml/badge.svg)](https://github.com/SourceRegistry/node-jwt/actions)
[![Codecov](https://img.shields.io/codecov/c/github/SourceRegistry/node-jwt)](https://codecov.io/gh/SourceRegistry/node-jwt)

A minimal, secure, and production-ready JWT (JSON Web Token) library for Node.js with zero dependencies. Supports all standard signing algorithms (HMAC, RSA, ECDSA, EdDSA, RSASSA-PSS), **automatic algorithm detection**, **JWK/JWKS**, and full claim validation.

✨ **Why another JWT library?**
Most JWT libraries are bloated, have security pitfalls, or lack proper TypeScript support. This library is:

* **Tiny**
* **Secure by default**
* **TypeScript-first** with full JSDoc
* **Zero external dependencies**
* **100% test coverage (Trying😉)**
* **Dual API**: Sync and Promise-based
* **Automatic algorithm detection based on key type**
* **Full JWK/JWKS support** (`import/export`, `toPublicJWK`, `x5c/x5t`, RFC 7638 thumbprints, kid-based key selection)

---

## 📦 Installation

```bash
npm install @sourceregistry/node-jwt
```

Requires Node.js ≥ 16

---

## 🚀 Quick Start

### Sync API (default)

```ts
import { sign, verify, decode } from '@sourceregistry/node-jwt';

// Sign (algorithm auto-detected)
const token = sign(
  { sub: '1234567890', name: 'John Doe', iat: Math.floor(Date.now() / 1000) },
  'your-secret-key'
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

// Sign (algorithm auto-detected)
const token = await sign(
  { sub: '1234567890', name: 'John Doe', iat: Math.floor(Date.now() / 1000) },
  'your-secret-key'
);

// Verify
try {
  const { payload } = await verify(token, 'your-secret-key', {
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

## 🧠 Algorithm Autodetection (New)

When `options.alg` is **omitted**, the library automatically selects the correct JWT algorithm **based on the signing key**.

### 🔑 Autodetection Rules

| Key Type                        | Detection Logic       | Selected Algorithm          |
| ------------------------------- | --------------------- | --------------------------- |
| Symmetric (`string` / `Buffer`) | Default HMAC          | `HS256`                     |
| RSA private key                 | PKCS#1 v1.5           | `RS256`                     |
| RSA-PSS private key             | Hash algorithm in key | `PS256` / `PS384` / `PS512` |
| EC P-256 (`prime256v1`)         | Curve name            | `ES256`                     |
| EC P-384 (`secp384r1`)          | Curve name            | `ES384`                     |
| EC P-521 (`secp521r1`)          | Curve name            | `ES512`                     |
| EC secp256k1                    | Curve name            | `ES256K`                    |
| Ed25519                         | Key type              | `EdDSA`                     |

> 💡 Node.js exposes OpenSSL curve names (`prime256v1`, `secp384r1`, etc.).
> These are automatically normalized to JOSE algorithms.

### ❌ Autodetection Errors

Autodetection fails for unsupported keys:

* Unsupported EC curve
* Unsupported RSA-PSS hash algorithm (e.g. `sha1`)
* Unsupported asymmetric key type (e.g. DSA)

---

## 🔑 Supported Algorithms

| Algorithm             | Type              | Secret Type          |
| --------------------- | ----------------- | -------------------- |
| HS256 / HS384 / HS512 | HMAC              | `string \| Buffer`   |
| RS256 / RS384 / RS512 | RSA               | Private / Public key |
| PS256 / PS384 / PS512 | RSA-PSS           | Private / Public key |
| ES256 / ES384 / ES512 | ECDSA             | Private / Public key |
| ES256K                | ECDSA (secp256k1) | Private / Public key |
| EdDSA                 | Ed25519           | Private / Public key |

> Keys may be PEM, DER, JWK, or Node.js `KeyObject`.

---

## 🧩 JWK / JWKS Support

* Import/export **JWK**: `importJWK()`, `exportJWK()`
* Convert to **public-only JWK**: `toPublicJWK()`
* Compute **RFC 7638 thumbprint**: `getJWKThumbprint()`
* Support **x5c/x5t** (X.509 cert chain + SHA-1 thumbprint)
* Normalize **JWKS** with auto-generated `kid` and `x5t`
* Resolve keys from **JWKS** by `kid` for verification
* Load remote **JWKS** with caching via `JWKS.fromWeb()`

### 🔹 Example: JWKS Key Selection

```ts
import { JWKS, JWK } from '@sourceregistry/node-jwt';

const keyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = JWK.toPublic(keyPair.publicKey);
const jwks = JWKS.normalize({ keys: [jwk] });

// Retrieve key by kid
const keyObject = JWKS.toKeyObject(jwks, jwk.kid);
```

### 🔹 Example: Remote JWKS (`fromWeb`)

```ts
import { JWKS } from '@sourceregistry/node-jwt';

const jwks = await JWKS.fromWeb('https://issuer.example', {
  ttl: 60_000,
  timeoutMs: 2_000
});

const jwk = await jwks.key('my-kid');
const keys = await jwks.list();
const rsaKeys = await jwks.find({ kty: 'RSA' });
const firstSigKey = await jwks.findFirst({ use: 'sig' });

// Force refresh
await jwks.refresh();

// Access cached JWKS snapshot
const current = jwks.export();
```

`fromWeb()` options:

* `fetch` — custom fetch implementation (for runtimes/framework adapters)
* `ttl` — cache TTL in ms (`0` disables automatic refresh)
* `timeoutMs` — network timeout in ms
* `endpointOverride` — custom endpoint (absolute or relative)
* `overrideEndpointCheck` — skip automatic `/.well-known/jwks.json` append
* `cache` — custom cache backend with `{ get(key), set(key, value) }`

### 🔹 Local Examples

See runnable examples in:

* `examples/jwt.example.ts`
* `examples/jwks.example.ts`

---

## 🛡️ Security Features

* ✅ Safe algorithm autodetection
* ✅ Strict algorithm whitelisting (`algorithms` option)
* ✅ Full RSASSA-PSS and Ed25519 support
* ✅ Time claim validation (`exp`, `nbf`, `iat`) with clock skew
* ✅ Claim validation (`iss`, `sub`, `aud`, `jti`)
* ✅ Maximum token age enforcement
* ✅ Timing-safe signature comparison
* ✅ No insecure defaults

---

## 🔏 ECDSA Signature Format: DER vs JOSE (New)

For **ECDSA** algorithms (`ES256`, `ES384`, `ES512`, `ES256K`) there are two common signature encodings:

- **DER** (ASN.1) — what Node.js produces by default
- **JOSE** (`r || s` raw signature) — required by the JWT/JWS spec and used by systems like **VAPID/Web Push (WNS)**

### Default behavior
By default, this library outputs **DER** signatures for `ES*` algorithms to match Node.js/OpenSSL defaults.

### Enable JOSE output
To generate spec-compliant JOSE ECDSA signatures, set:

- `signatureFormat: "jose"` in `sign()`

```ts
import { sign, verify } from "@sourceregistry/node-jwt";

const token = sign(
  { sub: "123", iat: Math.floor(Date.now() / 1000) },
  ecPrivateKey,
  { alg: "ES256", signatureFormat: "jose" }
);

// Verify JOSE-signed token
const result = verify(token, ecPublicKey, { signatureFormat: "jose" });
````

### Auto-detect verification (optional)

If enabled in your version, `verify()` can also validate JOSE ECDSA signatures without specifying `signatureFormat` (it will try DER first, then JOSE).
If you want strict behavior, pass `signatureFormat: "der"` or `signatureFormat: "jose"` explicitly.

> 💡 For VAPID/Web Push (e.g. Windows WNS endpoints), you typically need `ES256` with `signatureFormat: "jose"`.


## 📚 API Reference

### `sign(payload, secret, options?)`

* `alg` *(optional)* — If omitted, algorithm is auto-detected
* `kid` — Key ID
* `typ` — Token type (default: `"JWT"`)

### `verify(token, secret, options?)`

Includes algorithm whitelist protection and full claim validation.

**Error Codes include:**

* `INVALID_TOKEN`
* `INVALID_ALGORITHM`
* `ALGORITHM_NOT_ALLOWED`
* `INVALID_SIGNATURE`
* `TOKEN_EXPIRED`
* `TOKEN_NOT_ACTIVE`
* `TOKEN_TOO_OLD`
* `MISSING_*` / `INVALID_*`

### `decode(token)`

Decode a JWT without verification (**unsafe**).

---

## 🧪 Testing

* High branch coverage
* All algorithms + autodetection paths
* All failure modes
* Sync + Promise APIs
* Full JWK/JWKS coverage (import/export, x5c/x5t, thumbprint, kid selection)

```bash
npm test
npm run test:coverage
```

---

## 📦 Exports

| Import                              | Description |
| ----------------------------------- | ----------- |
| `@sourceregistry/node-jwt`          | Sync API    |
| `@sourceregistry/node-jwt/promises` | Promise API |

---

## 🙌 Contributing

PRs welcome!
Please add tests and maintain full coverage.

🔐 Security issues? Report responsibly: **[a.p.a.slaa@projectsource.nl](mailto:a.p.a.slaa@projectsource.nl)**

🔗 GitHub: [https://github.com/SourceRegistry/node-jwt](https://github.com/SourceRegistry/node-jwt)
📦 npm: [https://www.npmjs.com/package/@sourceregistry/node-jwt](https://www.npmjs.com/package/@sourceregistry/node-jwt)
