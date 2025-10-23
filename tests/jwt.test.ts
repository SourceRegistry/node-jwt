import {describe, expect, it} from 'vitest';
import {decode, JWTPayload, sign, SignatureAlgorithm, SupportedAlgorithm, verify} from '../src';
import {generateKeyPairSync, KeyLike} from 'crypto';

// --- Key Setup ---
const hmacSecret = 'my-super-secret';
const {publicKey: rsaPublicKey, privateKey: rsaPrivateKey} = generateKeyPairSync('rsa', {modulusLength: 2048});
const {publicKey: ecPublicKey, privateKey: ecPrivateKey} = generateKeyPairSync('ec', {namedCurve: 'P-256'});
const {publicKey: k1PublicKey, privateKey: k1PrivateKey} = generateKeyPairSync('ec', {namedCurve: 'secp256k1'});
const {publicKey: edPublicKey, privateKey: edPrivateKey} = generateKeyPairSync('ed25519');

const now = Math.floor(Date.now() / 1000);

const basePayload: JWTPayload = {
    sub: '1234567890',
    name: 'John Doe',
    iat: now,
};

// --- Algorithm Config Map ---
const algorithmConfig = {
    HS256: {signKey: hmacSecret, verifyKey: hmacSecret},
    HS384: {signKey: hmacSecret, verifyKey: hmacSecret},
    HS512: {signKey: hmacSecret, verifyKey: hmacSecret},
    RS256: {signKey: rsaPrivateKey, verifyKey: rsaPublicKey},
    RS384: {signKey: rsaPrivateKey, verifyKey: rsaPublicKey},
    RS512: {signKey: rsaPrivateKey, verifyKey: rsaPublicKey},
    ES256: {signKey: ecPrivateKey, verifyKey: ecPublicKey},
    ES384: {signKey: ecPrivateKey, verifyKey: ecPublicKey},
    ES512: {signKey: ecPrivateKey, verifyKey: ecPublicKey},
    ES256K: {signKey: k1PrivateKey, verifyKey: k1PublicKey},
    PS256: {signKey: rsaPrivateKey, verifyKey: rsaPublicKey},
    PS384: {signKey: rsaPrivateKey, verifyKey: rsaPublicKey},
    PS512: {signKey: rsaPrivateKey, verifyKey: rsaPublicKey},
    EdDSA: {signKey: edPrivateKey, verifyKey: edPublicKey},
} satisfies Record<SupportedAlgorithm, { signKey: KeyLike; verifyKey: KeyLike }>;

// --- Main Test Suite ---
describe('JWT Library', () => {
    // === Signing ===
    describe('sign()', () => {
        it('should sign with HS256 by default', () => {
            const token = sign(basePayload, hmacSecret);
            const parts = token.split('.');
            expect(parts).toHaveLength(3);
            expect(parts.every(p => /^[A-Za-z0-9_-]+$/.test(p))).toBe(true);
        });

        it('should include kid and typ in header when provided', () => {
            const token = sign(basePayload, hmacSecret, {alg: 'HS256', kid: 'test-key', typ: 'JWT'});
            const {header} = decode(token);
            expect(header.kid).toBe('test-key');
            expect(header.typ).toBe('JWT');
        });

        it('should throw on unsupported algorithm', () => {
            expect(() => sign(basePayload, hmacSecret, {alg: 'NONE' as any})).toThrow('Unsupported algorithm: NONE');
        });

        // Full algorithm coverage
        (Object.keys(algorithmConfig) as SupportedAlgorithm[]).forEach((alg) => {
            it(`should sign and verify with ${alg}`, () => {
                const {signKey, verifyKey} = algorithmConfig[alg];
                const token = sign(basePayload, signKey, {alg});
                const result = verify(token, verifyKey);
                expect(result.valid).toBe(true);
                if (result.valid) {
                    expect(result.payload).toEqual(basePayload);
                    expect(result.header.alg).toBe(alg);
                }
            });

            it(`should reject ${alg} with wrong verification key`, () => {
                const {signKey} = algorithmConfig[alg];
                const token = sign(basePayload, signKey, {alg});

                let wrongKey: KeyLike;
                if (alg.startsWith('HS')) {
                    wrongKey = 'wrong-secret';
                } else if (alg.startsWith('RS') || alg.startsWith('PS')) {
                    const {publicKey} = generateKeyPairSync('rsa', {modulusLength: 2048});
                    wrongKey = publicKey;
                } else if (alg.startsWith('ES')) {
                    const curve = alg === 'ES256K' ? 'secp256k1' : 'P-256';
                    const {publicKey} = generateKeyPairSync('ec', {namedCurve: curve as any});
                    wrongKey = publicKey;
                } else {
                    // EdDSA
                    const {publicKey} = generateKeyPairSync('ed25519');
                    wrongKey = publicKey;
                }

                const result = verify(token, wrongKey);
                expect(result.valid).toBe(false);
                if (!result.valid) {
                    expect(result.error.code).toBe('INVALID_SIGNATURE');
                }
            });
        });
    });

    // === Decoding ===
    describe('decode()', () => {
        it('should decode a valid token', () => {
            const token = sign(basePayload, hmacSecret);
            const decoded = decode(token);
            expect(decoded.header.typ).toBe('JWT');
            expect(decoded.payload).toEqual(basePayload);
            expect(typeof decoded.signature).toBe('string');
        });

        it('should throw on token with != 3 parts', () => {
            expect(() => decode('a.b')).toThrow('exactly 3 parts');
            expect(() => decode('a.b.c.d')).toThrow('exactly 3 parts');
        });

        it('should throw on malformed JSON', () => {
            expect(() => decode('a.b.c')).toThrow('malformed header or payload');
        });

        it('should throw on empty part', () => {
            expect(() => decode('.b.c')).toThrow('empty part');
            expect(() => decode('a..c')).toThrow('empty part');
            expect(() => decode('a.b.')).toThrow('empty part');
        });
    });

    // === Verification ===
    describe('verify()', () => {
        it('should return valid=true for correct token', () => {
            const token = sign(basePayload, hmacSecret);
            const result = verify(token, hmacSecret);
            expect(result.valid).toBe(true);
            if (result.valid) expect(result.payload).toEqual(basePayload);
        });

        it('should reject invalid signature', () => {
            const token = sign(basePayload, hmacSecret);
            const result = verify(token, 'wrong-secret');
            expect(result.valid).toBe(false);
            if (!result.valid) expect(result.error.code).toBe('INVALID_SIGNATURE');
        });

        it('should reject unsupported algorithm', () => {
            const forged = `${Buffer.from(JSON.stringify({
                alg: 'NONE',
                typ: 'JWT'
            })).toString('base64url')}.${Buffer.from(JSON.stringify(basePayload)).toString('base64url')}.sig`;
            const result = verify(forged, hmacSecret);
            expect(result.valid).toBe(false);
            if (!result.valid) expect(result.error.code).toBe('INVALID_ALGORITHM');
        });

        it('should reject wrong typ', () => {
            const token = sign(basePayload, hmacSecret, {typ: 'at+jwt'});
            const result = verify(token, hmacSecret);
            expect(result.valid).toBe(false);
            if (!result.valid) expect(result.error.code).toBe('INVALID_TYPE');
        });

        // --- Time Validation ---
        describe('time validation', () => {
            const past = now - 3600;
            const future = now + 3600;

            it('should reject expired token', () => {
                const token = sign({...basePayload, exp: past}, hmacSecret);
                const result = verify(token, hmacSecret);
                expect(result.valid).toBe(false);
                if (!result.valid) expect(result.error.code).toBe('TOKEN_EXPIRED');
            });

            it('should accept expired token when ignoreExpiration=true', () => {
                const token = sign({...basePayload, exp: past}, hmacSecret);
                const result = verify(token, hmacSecret, {ignoreExpiration: true});
                expect(result.valid).toBe(true);
            });

            it('should reject token not yet active (nbf)', () => {
                const token = sign({...basePayload, nbf: future}, hmacSecret);
                const result = verify(token, hmacSecret);
                expect(result.valid).toBe(false);
                if (!result.valid) expect(result.error.code).toBe('TOKEN_NOT_ACTIVE');
            });

            it('should reject token issued in the future (iat)', () => {
                const token = sign({...basePayload, iat: future}, hmacSecret);
                const result = verify(token, hmacSecret);
                expect(result.valid).toBe(false);
                if (!result.valid) expect(result.error.code).toBe('TOKEN_FUTURE_ISSUED');
            });

            it('should accept token with clock skew', () => {
                const token = sign({...basePayload, iat: now + 10}, hmacSecret);
                const result = verify(token, hmacSecret, {clockSkew: 15});
                expect(result.valid).toBe(true);
            });
        });

        // --- Algorithm Whitelist (Security) ---
        describe('algorithm whitelist', () => {
            it('should accept token with algorithm in whitelist', () => {
                const token = sign(basePayload, hmacSecret, {alg: 'HS256'});
                const result = verify(token, hmacSecret, {algorithms: ['HS256', 'HS384']});
                expect(result.valid).toBe(true);
            });

            it('should reject token with algorithm not in whitelist', () => {
                const token = sign(basePayload, hmacSecret, {alg: 'HS256'});
                const result = verify(token, hmacSecret, {algorithms: ['HS384', 'HS512']});
                expect(result.valid).toBe(false);
                if (!result.valid) {
                    expect(result.error.code).toBe('ALGORITHM_NOT_ALLOWED');
                    expect(result.error.reason).toContain('not in the allowed algorithms list');
                }
            });

            it('should reject RSA token when only HMAC is allowed', () => {
                const token = sign(basePayload, rsaPrivateKey, {alg: 'RS256'});
                const result = verify(token, rsaPublicKey, {algorithms: ['HS256']});
                expect(result.valid).toBe(false);
                if (!result.valid) expect(result.error.code).toBe('ALGORITHM_NOT_ALLOWED');
            });

            it('should accept when algorithms list is empty (no restriction)', () => {
                const token = sign(basePayload, hmacSecret, {alg: 'HS256'});
                const result = verify(token, hmacSecret, {algorithms: []});
                expect(result.valid).toBe(true);
            });

            it('should accept when algorithms option is not provided', () => {
                const token = sign(basePayload, hmacSecret, {alg: 'HS256'});
                const result = verify(token, hmacSecret);
                expect(result.valid).toBe(true);
            });
        });

        // --- Max Token Age ---
        describe('maximum token age validation', () => {
            it('should accept token within maxTokenAge', () => {
                const payload = {...basePayload, iat: now - 100};
                const token = sign(payload, hmacSecret);
                const result = verify(token, hmacSecret, {maxTokenAge: 200});
                expect(result.valid).toBe(true);
            });

            it('should reject token exceeding maxTokenAge', () => {
                const payload = {...basePayload, iat: now - 3600};
                const token = sign(payload, hmacSecret);
                const result = verify(token, hmacSecret, {maxTokenAge: 1800});
                expect(result.valid).toBe(false);
                if (!result.valid) {
                    expect(result.error.code).toBe('TOKEN_TOO_OLD');
                    expect(result.error.reason).toContain('exceeds maximum allowed age');
                }
            });

            it('should skip maxTokenAge validation when iat is missing', () => {
                const payload = {...basePayload, iat: undefined};
                const token = sign(payload, hmacSecret);
                const result = verify(token, hmacSecret, {maxTokenAge: 100});
                expect(result.valid).toBe(true);
            });

            it('should skip maxTokenAge validation when maxTokenAge is not provided', () => {
                const payload = {...basePayload, iat: now - 10000};
                const token = sign(payload, hmacSecret);
                const result = verify(token, hmacSecret);
                expect(result.valid).toBe(true);
            });
        });

        // --- Timing-Safe Comparison (Security) ---
        describe('timing-safe comparison', () => {
            it('should reject HMAC token with slightly different signature', () => {
                const token = sign(basePayload, hmacSecret, {alg: 'HS256'});
                const parts = token.split('.');
                const modifiedSig = parts[2].slice(0, -1) + (parts[2].slice(-1) === 'a' ? 'b' : 'a');
                const modifiedToken = `${parts[0]}.${parts[1]}.${modifiedSig}`;
                const result = verify(modifiedToken, hmacSecret);
                expect(result.valid).toBe(false);
                if (!result.valid) expect(result.error.code).toBe('INVALID_SIGNATURE');
            });

            it('should reject HS384 token with wrong signature length', () => {
                const token = sign(basePayload, hmacSecret, {alg: 'HS384'});
                const parts = token.split('.');
                const shorterSig = parts[2].slice(0, -5);
                const modifiedToken = `${parts[0]}.${parts[1]}.${shorterSig}`;
                const result = verify(modifiedToken, hmacSecret);
                expect(result.valid).toBe(false);
                if (!result.valid) expect(result.error.code).toBe('INVALID_SIGNATURE');
            });
        });

        // --- Combined Security Options ---
        describe('combined security options', () => {
            const fullPayload: JWTPayload = {
                ...basePayload,
                iss: 'https://secure-issuer.com',
                aud: 'secure-app',
                iat: now - 100,
                exp: now + 3600,
            };

            it('should validate all security options together', () => {
                const token = sign(fullPayload, rsaPrivateKey, {alg: 'RS256'});
                const result = verify(token, rsaPublicKey, {
                    algorithms: ['RS256'],
                    issuer: 'https://secure-issuer.com',
                    audience: 'secure-app',
                    maxTokenAge: 200,
                    clockSkew: 10,
                });
                expect(result.valid).toBe(true);
            });

            it('should reject when any security check fails', () => {
                const token = sign(fullPayload, rsaPrivateKey, {alg: 'RS256'});
                const result = verify(token, rsaPublicKey, {
                    algorithms: ['RS256'],
                    issuer: 'https://wrong-issuer.com', // intentional mismatch
                    audience: 'secure-app',
                    maxTokenAge: 200,
                });
                expect(result.valid).toBe(false);
                if (!result.valid) expect(result.error.code).toBe('INVALID_ISSUER');
            });
        });
    });

    // === Claim Validation ===
    describe('claim validation', () => {
        const fullPayload: JWTPayload = {
            ...basePayload,
            iss: 'https://issuer.example.com',
            sub: 'user123',
            aud: ['api.example.com', 'web.example.com'],
            jti: 'abc-123-xyz',
        };

        const token = sign(fullPayload, hmacSecret);

        it('should validate issuer', () => {
            const result = verify(token, hmacSecret, {issuer: 'https://issuer.example.com'});
            expect(result.valid).toBe(true);
        });

        it('should reject invalid issuer', () => {
            const result = verify(token, hmacSecret, {issuer: 'https://evil.com'});
            expect(result.valid).toBe(false);
            if (!result.valid) expect(result.error.code).toBe('INVALID_ISSUER');
        });

        it('should reject missing issuer when required', () => {
            const token = sign(basePayload, hmacSecret);
            const result = verify(token, hmacSecret, {issuer: 'expected'});
            expect(result.valid).toBe(false);
            if (!result.valid) {
                expect(result.error.code).toBe('MISSING_ISSUER');
            }
        });

        it('should reject missing subject when required', () => {
            const payload = {...basePayload, sub: undefined};
            const token = sign(payload, hmacSecret);
            const result = verify(token, hmacSecret, {subject: 'user123'});
            expect(result.valid).toBe(false);
            if (!result.valid) {
                expect(result.error.code).toBe('MISSING_SUBJECT');
            }
        });

        it('should reject missing audience when required', () => {
            const payload = {...basePayload, aud: undefined};
            const token = sign(payload, hmacSecret);
            const result = verify(token, hmacSecret, {audience: 'api'});
            expect(result.valid).toBe(false);
            if (!result.valid) {
                expect(result.error.code).toBe('MISSING_AUDIENCE');
            }
        });

        it('should reject missing jti when required', () => {
            const payload = {...basePayload, jti: undefined};
            const token = sign(payload, hmacSecret);
            const result = verify(token, hmacSecret, {jwtId: 'abc123'});
            expect(result.valid).toBe(false);
            if (!result.valid) {
                expect(result.error.code).toBe('MISSING_JTI');
            }
        });


        it('should reject when subject is mismatched', () => {
            const token = sign({
                ...fullPayload,
                sub: 'https://right-issuer.com'
            }, rsaPrivateKey, {alg: 'RS256'});
            const result = verify(token, rsaPublicKey, {
                algorithms: ['RS256'],
                subject: 'https://wrong-issuer.com', // intentional mismatch
                audience: 'secure-app',
                maxTokenAge: 200,
            });
            expect(result.valid).toBe(false);
            if (!result.valid) expect(result.error.code).toBe('INVALID_SUBJECT');
        });


        it('should also work with audience as string[] input', () => {
            const token = sign({
                ...fullPayload,
                aud: 'secure-app'
            }, rsaPrivateKey, {alg: 'RS256'});
            const result = verify(token, rsaPublicKey, {
                algorithms: ['RS256'],
                audience: ['insecure-app', 'secure-app'],
                maxTokenAge: 200,
            });
            expect(result.valid).toBe(true);
        });

        it('should also work with audience as string[] payload', () => {
            const token = sign({
                ...fullPayload,
                aud: ['secure-app', 'secure-app2']
            }, rsaPrivateKey, {alg: 'RS256'});
            const result = verify(token, rsaPublicKey, {
                algorithms: ['RS256'],
                audience: ['secure-app'],
                maxTokenAge: 200,
            });
            expect(result.valid).toBe(true);
        });


        it('should reject when audience is mismatched', () => {
            const token = sign({
                ...fullPayload,
                aud: 'secure-app'
            }, rsaPrivateKey, {alg: 'RS256'});
            const result = verify(token, rsaPublicKey, {
                algorithms: ['RS256'],
                audience: 'insecure-app',
                maxTokenAge: 200,
            });
            expect(result.valid).toBe(false);
            if (!result.valid) expect(result.error.code).toBe('INVALID_AUDIENCE');
        });

        it('should reject when jti is mismatched', () => {
            const token = sign(fullPayload, rsaPrivateKey, {alg: 'RS256'});
            const result = verify(token, rsaPublicKey, {
                algorithms: ['RS256'],
                jwtId: 'abc-123-xy',
                maxTokenAge: 200,
            });
            expect(result.valid).toBe(false);
            if (!result.valid) expect(result.error.code).toBe('INVALID_JTI');
        });

    });

    describe('SignatureAlgorithms', () => {
        Object.entries(SignatureAlgorithm).map(([alg, {verify}]) => {
            it(`${alg} verify should return false`, () => {
                expect(verify('testing123', '--123', '')).toBe(false);
            });
        })

        describe('EdDSA special signature test', () => {
            const {signKey, verifyKey} = algorithmConfig['EdDSA'];
            const {sign, verify} = SignatureAlgorithm.EdDSA;

            it('should also sign with buffer as data', () => {
                const input = Buffer.from('testing123', 'utf8');
                expect(sign(input, signKey)).toBeTypeOf('string');
            });
            it('should also verify with buffer as data', () => {
                const input = Buffer.from('testing123', 'utf8');
                expect(verify(input, verifyKey,'')).toBeTypeOf("boolean");
            });
        })

    });
});
