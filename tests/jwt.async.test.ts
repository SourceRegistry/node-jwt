import { describe, it, expect } from 'vitest';
import * as jwt from '../src/promises';
import { generateKeyPairSync } from 'node:crypto';

const { publicKey: rsaPub, privateKey: rsaPriv } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const { publicKey: ecPub, privateKey: ecPriv } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

const secret = 'my-secret';
const now = Math.floor(Date.now() / 1000);
const payload = { sub: '123', iat: now };

describe('JWT Promises API', () => {
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

    it('should reject on invalid signature', async () => {
        const token = await jwt.sign(payload, secret);
        await expect(jwt.verify(token, 'wrong-secret')).rejects.toMatchObject({
            code: 'INVALID_SIGNATURE',
            reason: expect.any(String)
        });
    });

    it('should reject on expired token', async () => {
        const expired = { ...payload, exp: now - 100 };
        const token = await jwt.sign(expired, secret);
        await expect(jwt.verify(token, secret)).rejects.toMatchObject({
            code: 'TOKEN_EXPIRED'
        });
    });

    it('should accept expired token with ignoreExpiration', async () => {
        const expired = { ...payload, exp: now - 100 };
        const token = await jwt.sign(expired, secret);
        const result = await jwt.verify(token, secret, { ignoreExpiration: true });
        expect(result.payload).toEqual(expired);
    });

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

    it('should reject malformed token in decode', async () => {
        await expect(jwt.decode('a.b')).rejects.toThrow('exactly 3 parts');
    });

    it('should reject unsupported algorithm', async () => {
        const token = `${Buffer.from(JSON.stringify({ alg: 'NONE', typ: 'JWT' })).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.sig`;
        await expect(jwt.verify(token, secret)).rejects.toMatchObject({
            code: 'INVALID_ALGORITHM'
        });
    });

    it('should handle clock skew', async () => {
        const futurePayload = { ...payload, iat: now + 10 };
        const token = await jwt.sign(futurePayload, secret);
        const result = await jwt.verify(token, secret, { clockSkew: 15 });
        expect(result.payload).toEqual(futurePayload);
    });

    it('should preserve custom claims', async () => {
        const customPayload = { ...payload, custom: 'value', roles: ['admin'] };
        const token = await jwt.sign(customPayload, secret);
        const result = await jwt.verify(token, secret);
        expect(result.payload.custom).toBe('value');
        expect((result.payload.roles as string[])).toEqual(['admin']);
    });
});
