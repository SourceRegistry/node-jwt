import {describe, expect, it} from 'vitest';
import {decode, JWTPayload, sign, SupportedAlgorithms, verify} from '../src';

// Generate test keys
import {generateKeyPairSync} from 'crypto';

const { publicKey: rsaPublicKey, privateKey: rsaPrivateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
});

const { publicKey: ecPublicKey, privateKey: ecPrivateKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
});

const hmacSecret = 'my-super-secret';
const hmacSecretBuffer = Buffer.from(hmacSecret);

describe('JWT Library', () => {
    const now = Math.floor(Date.now() / 1000);
    const future = now + 3600;
    const past = now - 3600;

    const basePayload: JWTPayload = {
        sub: '1234567890',
        name: 'John Doe',
        iat: now,
    };

    // Test all supported algorithms

    describe('sign()', () => {
        it('should sign with HS256 by default', () => {
            const token = sign(basePayload, hmacSecret);
            const parts = token.split('.');
            expect(parts).toHaveLength(3);
            expect(parts[0]).toMatch(/^[A-Za-z0-9_-]+$/);
            expect(parts[1]).toMatch(/^[A-Za-z0-9_-]+$/);
            expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/);
        });

        it('should include kid and typ in header when provided', () => {
            const token = sign(basePayload, hmacSecret, { alg: 'HS256', kid: 'test-key', typ: 'JWT' });
            const { header } = decode(token);
            expect(header.kid).toBe('test-key');
            expect(header.typ).toBe('JWT');
        });

        it('should throw on unsupported algorithm', () => {
            expect(() => sign(basePayload, hmacSecret, { alg: 'NONE' as any })).toThrow(
                'Unsupported algorithm: NONE'
            );
        });

        SupportedAlgorithms.forEach((alg) => {
            it(`should sign and verify with ${alg}`, () => {
                let secret;
                if (alg.startsWith('HS')) {
                    secret = hmacSecret;
                } else if (alg.startsWith('RS')) {
                    secret = rsaPrivateKey;
                } else if (alg.startsWith('ES')) {
                    secret = ecPrivateKey;
                } else {
                    throw new Error(`Unknown algorithm: ${alg}`);
                }

                const token = sign(basePayload, secret, { alg });
                const result = verify(token,
                    alg.startsWith('HS') ? hmacSecret :
                        alg.startsWith('RS') ? rsaPublicKey : ecPublicKey
                );

                expect(result.valid).toBe(true);
                if (result.valid) {
                    expect(result.payload).toEqual(basePayload);
                    expect(result.header.alg).toBe(alg);
                }
            });
        });
    });

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
            const badToken = 'a.b.c'; // base64url decode of 'a' is invalid JSON
            expect(() => decode(badToken)).toThrow('malformed header or payload');
        });

        it('should throw on empty part', () => {
            expect(() => decode('.b.c')).toThrow('empty part');
            expect(() => decode('a..c')).toThrow('empty part');
            expect(() => decode('a.b.')).toThrow('empty part');
        });
    });

    describe('verify()', () => {
        it('should return valid=true for correct token', () => {
            const token = sign(basePayload, hmacSecret);
            const result = verify(token, hmacSecret);
            expect(result.valid).toBe(true);
            if (result.valid) {
                expect(result.payload).toEqual(basePayload);
            }
        });

        it('should reject invalid signature', () => {
            const token = sign(basePayload, hmacSecret);
            const result = verify(token, 'wrong-secret');
            expect(result.valid).toBe(false);
            if (!(result.valid)) {
                expect(result.error.code).toBe('INVALID_SIGNATURE');
            }
        });

        it('should reject unsupported algorithm', () => {
            const header = { alg: 'NONE', typ: 'JWT' };
            const forged = `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${Buffer.from(JSON.stringify(basePayload)).toString('base64url')}.signature`;
            const result = verify(forged, hmacSecret);
            expect(result.valid).toBe(false);
            if (!(result.valid)) {
                expect(result.error.code).toBe('INVALID_ALGORITHM');
            }
        });

        it('should reject wrong typ', () => {
            const token = sign(basePayload, hmacSecret, { typ: 'at+jwt' });
            const result = verify(token, hmacSecret);
            expect(result.valid).toBe(false);
            if (!(result.valid)) {
                expect(result.error.code).toBe('INVALID_TYPE');
            }
        });

        describe('time validation', () => {
            it('should reject expired token', () => {
                const expiredPayload = { ...basePayload, exp: past };
                const token = sign(expiredPayload, hmacSecret);
                const result = verify(token, hmacSecret);
                expect(result.valid).toBe(false);
                if (!(result.valid)) {
                    expect(result.error.code).toBe('TOKEN_EXPIRED');
                }
            });

            it('should accept token with ignoreExpiration', () => {
                const expiredPayload = { ...basePayload, exp: past };
                const token = sign(expiredPayload, hmacSecret);
                const result = verify(token, hmacSecret, { ignoreExpiration: true });
                expect(result.valid).toBe(true);
            });

            it('should reject token not yet valid (nbf)', () => {
                const futurePayload = { ...basePayload, nbf: future };
                const token = sign(futurePayload, hmacSecret);
                const result = verify(token, hmacSecret);
                expect(result.valid).toBe(false);
                if (!(result.valid)) {
                    expect(result.error.code).toBe('TOKEN_NOT_ACTIVE');
                }
            });

            it('should reject token issued in the future (iat)', () => {
                const futurePayload = { ...basePayload, iat: future };
                const token = sign(futurePayload, hmacSecret);
                const result = verify(token, hmacSecret);
                expect(result.valid).toBe(false);
                if (!(result.valid)) {
                    expect(result.error.code).toBe('TOKEN_FUTURE_ISSUED');
                }
            });

            it('should accept token with clock skew', () => {
                const slightlyFuturePayload = { ...basePayload, iat: now + 10 };
                const token = sign(slightlyFuturePayload, hmacSecret);
                const result = verify(token, hmacSecret, { clockSkew: 15 });
                expect(result.valid).toBe(true);
            });
        });

        describe('algorithm-specific verification', () => {
            const testAlgorithms = ['HS256', 'RS256', 'ES256'] as const;

            testAlgorithms.forEach((alg) => {
                it(`should verify ${alg} correctly`, () => {
                    let secret, publicKey;
                    if (alg === 'HS256') {
                        secret = hmacSecret;
                        publicKey = hmacSecret;
                    } else if (alg === 'RS256') {
                        secret = rsaPrivateKey;
                        publicKey = rsaPublicKey;
                    } else {
                        secret = ecPrivateKey;
                        publicKey = ecPublicKey;
                    }

                    const token = sign(basePayload, secret, { alg });
                    const result = verify(token, publicKey);
                    expect(result.valid).toBe(true);
                    if (result.valid) {
                        expect(result.header.alg).toBe(alg);
                    }
                });

                it(`should reject ${alg} with wrong key`, () => {
                    let secret, wrongKey;
                    if (alg === 'HS256') {
                        secret = hmacSecret;
                        wrongKey = 'wrong';
                    } else if (alg === 'RS256') {
                        secret = rsaPrivateKey;
                        // Generate a different RSA key
                        const { publicKey: otherPub } = generateKeyPairSync('rsa', { modulusLength: 2048 });
                        wrongKey = otherPub;
                    } else {
                        secret = ecPrivateKey;
                        const { publicKey: otherPub } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
                        wrongKey = otherPub;
                    }

                    const token = sign(basePayload, secret, { alg });
                    const result = verify(token, wrongKey);
                    expect(result.valid).toBe(false);
                    if (!(result.valid)) {
                        expect(result.error.code).toBe('INVALID_SIGNATURE');
                    }
                });
            });
        });
    });

    describe('error handling', () => {
        it('should return INVALID_TOKEN when decode fails due to invalid structure', () => {
            const result = verify('a.b', 'secret'); // only 2 parts
            expect(result.valid).toBe(false);
            if (!(result.valid)) {
                expect(result.error.code).toBe('INVALID_TOKEN');
                expect(result.error.reason).toContain('exactly 3 parts');
            }
        });

        it('should return INVALID_TOKEN when decode fails due to invalid base64', () => {
            const result = verify('!!!.!!!.!!!', 'secret');
            expect(result.valid).toBe(false);
            if (!(result.valid)) {
                expect(result.error.code).toBe('INVALID_TOKEN');
                expect(result.error.reason).toContain('malformed header or payload');
            }
        });
    });

    describe('edge cases', () => {
        it('should handle custom claims', () => {
            const payload = { ...basePayload, custom: 'value', nested: { a: 1 } };
            const token = sign(payload, hmacSecret);
            const result = verify(token, hmacSecret);
            expect(result.valid).toBe(true);
            if (result.valid) {
                expect(result.payload.custom).toBe('value');
                expect((result.payload.nested as any).a).toBe(1);
            }
        });

        it('should handle audience as string or array', () => {
            let token = sign({ ...basePayload, aud: 'my-app' }, hmacSecret);
            expect(verify(token, hmacSecret).valid).toBe(true);

            token = sign({ ...basePayload, aud: ['app1', 'app2'] }, hmacSecret);
            expect(verify(token, hmacSecret).valid).toBe(true);
        });

        it('should work with Buffer secret', () => {
            const token = sign(basePayload, hmacSecretBuffer);
            const result = verify(token, hmacSecretBuffer);
            expect(result.valid).toBe(true);
        });
    });
});
