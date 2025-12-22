import { describe, it, expect } from 'vitest';
import * as jwt from '../src/promises';
import { generateKeyPairSync } from 'node:crypto';

const { publicKey: rsaPub, privateKey: rsaPriv } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const { publicKey: ecPub, privateKey: ecPriv } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const { publicKey: edPub, privateKey: edPriv } = generateKeyPairSync('ed25519');

const secret = 'my-secret';
const now = Math.floor(Date.now() / 1000);
const payload = { sub: '123', iat: now };

describe('JWT Promises API', () => {
    // --- Signing & Basic Verification ---
    it('should sign and verify with HS256', async () => {
        const token = await jwt.sign(payload, secret);
        const result = await jwt.verify(token, secret);
        expect(result.payload).toEqual(payload);
        expect(result.header.alg).toBe('HS256');
    });

    it('should decode token', async () => {
        const token = await jwt.sign(payload, secret);
        const decoded = await jwt.decode(token);
        expect(decoded.payload).toEqual(payload);
        expect(decoded.signature).toBeDefined();
    });

    // --- Error Cases (Throwing) ---
    it('should reject on invalid signature', async () => {
        const token = await jwt.sign(payload, secret);
        await expect(jwt.verify(token, 'wrong-secret')).rejects.toMatchObject({
            code: 'INVALID_SIGNATURE',
        });
    });

    it('should reject on expired token', async () => {
        const expired = { ...payload, exp: now - 100 };
        const token = await jwt.sign(expired, secret);
        await expect(jwt.verify(token, secret)).rejects.toMatchObject({
            code: 'TOKEN_EXPIRED',
        });
    });

    it('should accept expired token with ignoreExpiration', async () => {
        const expired = { ...payload, exp: now - 100 };
        const token = await jwt.sign(expired, secret);
        const result = await jwt.verify(token, secret, { ignoreExpiration: true });
        expect(result.payload).toEqual(expired);
    });

    it('should reject malformed token in decode', async () => {
        await expect(jwt.decode('a.b')).rejects.toThrow('exactly 3 parts');
    });

    it('should reject unsupported algorithm', async () => {
        const forged = `${Buffer.from(JSON.stringify({ alg: 'NONE', typ: 'JWT' })).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.sig`;
        await expect(jwt.verify(forged, secret)).rejects.toMatchObject({
            code: 'INVALID_ALGORITHM',
        });
    });

    it('should reject wrong typ', async () => {
        const token = await jwt.sign(payload, secret, { typ: 'at+jwt' });
        await expect(jwt.verify(token, secret)).rejects.toMatchObject({
            code: 'INVALID_TYPE',
        });
    });

    // --- Asymmetric Algorithms ---
    it('should work with RSA', async () => {
        const token = await jwt.sign(payload, rsaPriv, { alg: 'RS256' });
        const result = await jwt.verify(token, rsaPub);
        expect(result.payload).toEqual(payload);
    });

    it('should work with ECDSA', async () => {
        const token = await jwt.sign(payload, ecPriv, { alg: 'ES256' });
        const result = await jwt.verify(token, ecPub);
        expect(result.payload).toEqual(payload);
    });

    it('should work with EdDSA', async () => {
        const token = await jwt.sign(payload, edPriv, { alg: 'EdDSA' });
        const result = await jwt.verify(token, edPub);
        expect(result.payload).toEqual(payload);
    });

    // --- Time & Clock Skew ---
    it('should handle clock skew', async () => {
        const futurePayload = { ...payload, iat: now + 10 };
        const token = await jwt.sign(futurePayload, secret);
        const result = await jwt.verify(token, secret, { clockSkew: 15 });
        expect(result.payload).toEqual(futurePayload);
    });

    it('should reject token not yet active (nbf)', async () => {
        const futurePayload = { ...payload, nbf: now + 100 };
        const token = await jwt.sign(futurePayload, secret);
        await expect(jwt.verify(token, secret)).rejects.toMatchObject({
            code: 'TOKEN_NOT_ACTIVE',
        });
    });

    // --- Security: Algorithm Whitelist ---
    it('should reject algorithm not in whitelist', async () => {
        const token = await jwt.sign(payload, secret, { alg: 'HS256' });
        await expect(
            jwt.verify(token, secret, { algorithms: ['HS384'] })
        ).rejects.toMatchObject({
            code: 'ALGORITHM_NOT_ALLOWED',
        });
    });

    it('should accept algorithm in whitelist', async () => {
        const token = await jwt.sign(payload, secret, { alg: 'HS256' });
        const result = await jwt.verify(token, secret, { algorithms: ['HS256', 'RS256'] });
        expect(result.payload).toEqual(payload);
    });

    // --- Max Token Age ---
    it('should reject token exceeding maxTokenAge', async () => {
        const oldPayload = { ...payload, iat: now - 3600 };
        const token = await jwt.sign(oldPayload, secret);
        await expect(
            jwt.verify(token, secret, { maxTokenAge: 1800 })
        ).rejects.toMatchObject({
            code: 'TOKEN_TOO_OLD',
        });
    });

    it('should skip maxTokenAge if iat missing', async () => {
        const noIatPayload = { ...payload, iat: undefined };
        const token = await jwt.sign(noIatPayload, secret);
        const result = await jwt.verify(token, secret, { maxTokenAge: 10 });
        expect(result.payload).toEqual(noIatPayload);
    });

    // --- Custom Claims & Edge Cases ---
    it('should preserve custom claims', async () => {
        const customPayload = { ...payload, custom: 'value', roles: ['admin'] };
        const token = await jwt.sign(customPayload, secret);
        const result = await jwt.verify(token, secret);
        expect(result.payload.custom).toBe('value');
        expect(result.payload.roles).toEqual(['admin']);
    });

    it('should work with Buffer secret', async () => {
        const bufSecret = Buffer.from(secret);
        const token = await jwt.sign(payload, bufSecret);
        const result = await jwt.verify(token, bufSecret);
        expect(result.payload).toEqual(payload);
    });

    // --- Combined Options ---
    it('should validate issuer, audience, and algorithm together', async () => {
        const fullPayload = {
            ...payload,
            iss: 'https://example.com',
            aud: 'my-app',
        };
        const token = await jwt.sign(fullPayload, rsaPriv, { alg: 'RS256' });
        const result = await jwt.verify(token, rsaPub, {
            algorithms: ['RS256'],
            issuer: 'https://example.com',
            audience: 'my-app',
        });
        expect(result.payload).toEqual(fullPayload);
    });

    it('should reject on issuer mismatch', async () => {
        const fullPayload = { ...payload, iss: 'https://example.com' };
        const token = await jwt.sign(fullPayload, secret);
        await expect(
            jwt.verify(token, secret, { issuer: 'https://evil.com' })
        ).rejects.toMatchObject({
            code: 'INVALID_ISSUER',
        });
    });
});
