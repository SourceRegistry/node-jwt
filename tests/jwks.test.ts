import {describe, expect, it} from 'vitest';

import {createSecretKey, generateKeyPairSync, KeyObject} from 'crypto';
import {JWK, JWKS} from "../src";


describe('JWK and JWKS extensions', () => {

    describe('JWKS extension', () => {
        it('exports public-only JWK', () => {
            const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

            const jwk = JWK.toPublic(privateKey);
            expect(jwk.kty).toBe('RSA');
            expect((jwk as any).d).toBeUndefined();
        });

        it('creates RFC 7638 thumbprint', () => {
            const { publicKey } = generateKeyPairSync('ed25519');
            const jwk = JWK.export(publicKey);

            const thumbprint = JWK.thumbprint(jwk);
            expect(typeof thumbprint).toBe('string');
            expect(thumbprint.length).toBeGreaterThan(10);
        });

        it('throws on unsupported JWK thumbprint type', () => {
            expect(() =>
                JWK.thumbprint({ kty: 'foo' } as any)
            ).toThrow('Unsupported JWK key type');
        });

        it('resolves key from JWKS using kid', () => {
            const { publicKey } = generateKeyPairSync('ec', {
                namedCurve: 'prime256v1'
            });

            const jwk = JWK.export(publicKey);
            jwk.kid = 'my-key';

            const key = JWKS.toKeyObject({ keys: [jwk] }, 'my-key');
            expect(key.asymmetricKeyType).toBe('ec');
        });

        it('falls back to single-key JWKS', () => {
            const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
            const jwk = JWK.export(publicKey);

            const key = JWKS.toKeyObject({ keys: [jwk] });
            expect(key.asymmetricKeyType).toBe('rsa');
        });

        it('throws when key not found in JWKS', () => {
            expect(() =>
                JWKS.toKeyObject({ keys: [] }, 'kid')
            ).toThrow('Key not found in JWKS');
        });

        it('normalizes JWKS with missing kid', () => {
            const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
            const jwk = JWK.export(publicKey);

            const normalized = JWKS.normalize({ keys: [jwk] });
            expect(normalized.keys[0].kid).toBeDefined();
        });
    });

    describe('JWK extension', () => {
        // RSA
        it('exports and imports RSA private key', () => {
            const {privateKey} = generateKeyPairSync('rsa', {
                modulusLength: 2048
            });

            const jwk = JWK.export(privateKey);
            expect(jwk.kty).toBe('RSA');
            expect('d' in jwk).toBe(true);

            const key = JWK.import(jwk);
            expect(key.type).toBe('private');
            expect(key.asymmetricKeyType).toBe('rsa');
        });

        it('imports RSA public key when d is missing', () => {
            const {publicKey} = generateKeyPairSync('rsa', {
                modulusLength: 2048
            });

            const jwk = JWK.export(publicKey);
            expect(jwk.kty).toBe('RSA');
            expect('d' in jwk).toBe(false);

            const key = JWK.import(jwk);
            expect(key.type).toBe('public');
            expect(key.asymmetricKeyType).toBe('rsa');
        });

        //EC
        it('exports and imports EC P-256 private key', () => {
            const {privateKey} = generateKeyPairSync('ec', {
                namedCurve: 'prime256v1'
            });

            const jwk = JWK.export(privateKey);
            expect(jwk.kty).toBe('EC');
            // @ts-ignore
            expect(jwk.crv).toBe('P-256');

            const key = JWK.import(jwk);
            expect(key.type).toBe('private');
            expect(key.asymmetricKeyType).toBe('ec');
        });

        //OKP (Ed25519)
        it('exports and imports OKP Ed25519 private key', () => {
            const {privateKey} = generateKeyPairSync('ed25519');

            const jwk = JWK.export(privateKey);
            expect(jwk.kty).toBe('OKP');
            // @ts-ignore
            expect(jwk.crv).toBe('Ed25519');

            const key = JWK.import(jwk);
            expect(key.type).toBe('private');
            expect(key.asymmetricKeyType).toBe('ed25519');
        });

        // oct (HMAC)
        it('exports and imports oct (symmetric) key', () => {
            const secret = createSecretKey(Buffer.from('super-secret'));

            const jwk = JWK.export(secret);
            expect(jwk.kty).toBe('oct');
            // @ts-ignore
            expect(jwk.k).toBeDefined();

            const key = JWK.import(jwk);
            expect(key.type).toBe('secret');
        });

        it('throws on invalid oct JWK', () => {
            const badJwk = {kty: 'oct'} as any;

            expect(() => JWK.import(badJwk))
                .toThrow('Invalid oct JWK: missing "k"');
        });

        // Errors
        it('throws on unsupported JWK type', () => {
            const badJwk = {kty: 'foo'} as any;

            expect(() => JWK.import(badJwk))
                .toThrow('Unsupported JWK key type: foo');
        });

        it('throws on invalid JWK input', () => {
            expect(() => JWK.import(null as any))
                .toThrow('Invalid JWK');
        });

        it('throws on invalid KeyObject export', () => {
            expect(() => JWK.export(null as unknown as KeyObject))
                .toThrow('Invalid KeyObject');
        });
    });

});
