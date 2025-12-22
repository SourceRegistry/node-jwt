import {describe, expect, it} from 'vitest';

import {generateKeyPairSync} from 'crypto';
import {JWK, JWKS} from "../src/promises";


describe('JWKS promises API', () => {

    it('exports and imports JWK', async () => {
        const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

        const jwk = await JWK.export(privateKey);
        const key = await JWK.import(jwk);

        expect(key.asymmetricKeyType).toBe('rsa');
    });


    it('creates RFC 7638 thumbprint', async () => {
        const { publicKey } = generateKeyPairSync('ed25519');
        const jwk = await JWK.export(publicKey);

        const thumbprint = await JWK.thumbprint(jwk);
        expect(typeof thumbprint).toBe('string');
        expect(thumbprint.length).toBeGreaterThan(10);
    });

    it('exports public JWK', async () => {
        const { privateKey } = generateKeyPairSync('ed25519');
        const jwk = await JWK.toPublic(privateKey);

        expect(jwk.kty).toBe('OKP');
        expect((jwk as any).d).toBeUndefined();
    });

    it('resolves key from JWKS', async () => {
        const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
        const jwk = await JWK.export(publicKey);
        jwk.kid = 'test';

        const key = await JWKS.toKeyObject({ keys: [jwk] }, 'test');
        expect(key.asymmetricKeyType).toBe('rsa');
    });

    it('normalizes JWKS', async () => {
        const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
        const jwk = await JWK.export(publicKey);

        const normalized = await JWKS.normalize({ keys: [jwk] });
        expect(normalized.keys[0].kid).toBeDefined();
    });

    describe('JWKS with x5c/x5t', () => {

        it('computes x5t from x5c', async () => {
            const certBase64 = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvf...'; // dummy
            const jwk = { kty: 'RSA', n: '...', e: 'AQAB', x5c: [certBase64] };

            const x5t = await JWK.computeX5T(jwk as any);
            expect(x5t).toBeDefined();
            expect(typeof x5t).toBe('string');
        });

        it('normalize adds kid and x5t', async () => {
            const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
            const jwk = await JWK.export(publicKey);
            jwk.x5c = ['MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvf...'];

            const normalized = await JWKS.normalize({ keys: [jwk] });
            expect(normalized.keys[0].kid).toBeDefined();
            expect(normalized.keys[0].x5t).toBeDefined();
        });

    });

});
