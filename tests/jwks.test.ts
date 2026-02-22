import {describe, expect, it, vi} from 'vitest';

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

        it('creates RFC 7638 thumbprint for EC and oct keys', () => {
            const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
            const ecJwk = JWK.export(publicKey);
            const ecThumbprint = JWK.thumbprint(ecJwk);
            expect(typeof ecThumbprint).toBe('string');
            expect(ecThumbprint.length).toBeGreaterThan(10);

            const octThumbprint = JWK.thumbprint({ kty: 'oct', k: Buffer.from('secret').toString('base64url') });
            expect(typeof octThumbprint).toBe('string');
            expect(octThumbprint.length).toBeGreaterThan(10);
        });

        it('throws on unsupported JWK thumbprint type', () => {
            expect(() =>
                JWK.thumbprint({ kty: 'foo' } as any)
            ).toThrow('Unsupported JWK key type');
        });

        it('throws on invalid JWK thumbprint input', () => {
            expect(() =>
                JWK.thumbprint(null as any)
            ).toThrow('Invalid JWK');
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

        it('fromWeb prefetches and resolves by kid', async () => {
            const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
            const jwk = JWK.export(publicKey);
            jwk.kid = 'remote-kid';

            const fetchMock = vi.fn(async () => ({
                ok: true,
                status: 200,
                statusText: 'OK',
                json: async () => ({ keys: [jwk] })
            })) as unknown as typeof fetch;

            const resolver = await JWKS.fromWeb('https://issuer.example', { fetch: fetchMock });
            const key = await resolver.key('remote-kid');

            expect(fetchMock).toHaveBeenCalledTimes(1);
            expect(fetchMock).toHaveBeenCalledWith(
                'https://issuer.example/.well-known/jwks.json',
                expect.objectContaining({ signal: expect.any(AbortSignal) })
            );
            expect(key?.kty).toBe('RSA');
        });

        it('fromWeb uses endpoint override and supports relative endpoints', async () => {
            const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
            const jwk = JWK.export(publicKey);
            jwk.kid = 'relative-endpoint-kid';

            const fetchMock = vi.fn(async () => ({
                ok: true,
                status: 200,
                statusText: 'OK',
                json: async () => ({ keys: [jwk] })
            })) as unknown as typeof fetch;

            const resolver = await JWKS.fromWeb('https://issuer.example/base', {
                fetch: fetchMock,
                endpointOverride: '/api/jwks'
            });

            await resolver.key('relative-endpoint-kid');
            expect(fetchMock).toHaveBeenCalledWith(
                'https://issuer.example/api/jwks',
                expect.objectContaining({ signal: expect.any(AbortSignal) })
            );
        });

        it('fromWeb accepts full JWKS URLs without appending', async () => {
            const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
            const jwk = JWK.export(publicKey);
            jwk.kid = 'already-jwks';

            const fetchMock = vi.fn(async () => ({
                ok: true,
                status: 200,
                statusText: 'OK',
                json: async () => ({ keys: [jwk] })
            })) as unknown as typeof fetch;

            const resolver = await JWKS.fromWeb('https://issuer.example/.well-known/jwks.json', { fetch: fetchMock });
            await resolver.key('already-jwks');

            expect(fetchMock).toHaveBeenCalledWith(
                'https://issuer.example/.well-known/jwks.json',
                expect.objectContaining({ signal: expect.any(AbortSignal) })
            );
        });

        it('fromWeb respects overrideEndpointCheck and does not append jwks path', async () => {
            const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
            const jwk = JWK.export(publicKey);
            jwk.kid = 'custom-endpoint';

            const fetchMock = vi.fn(async () => ({
                ok: true,
                status: 200,
                statusText: 'OK',
                json: async () => ({ keys: [jwk] })
            })) as unknown as typeof fetch;

            const resolver = await JWKS.fromWeb('https://issuer.example/custom', {
                fetch: fetchMock,
                overrideEndpointCheck: true
            });
            await resolver.key('custom-endpoint');

            expect(fetchMock).toHaveBeenCalledWith(
                'https://issuer.example/custom',
                expect.objectContaining({ signal: expect.any(AbortSignal) })
            );
        });

        it('fromWeb keeps raw endpointOverride when URL parsing fails', async () => {
            const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
            const jwk = JWK.export(publicKey);
            jwk.kid = 'raw-override';

            const fetchMock = vi.fn(async () => ({
                ok: true,
                status: 200,
                statusText: 'OK',
                json: async () => ({ keys: [jwk] })
            })) as unknown as typeof fetch;

            const resolver = await JWKS.fromWeb('https://issuer.example', {
                fetch: fetchMock,
                endpointOverride: 'http://['
            });
            await resolver.key('raw-override');

            expect(fetchMock).toHaveBeenCalledWith(
                'http://[',
                expect.objectContaining({ signal: expect.any(AbortSignal) })
            );
        });

        it('fromWeb ttl=0 does not auto-refresh, but reload forces fetch', async () => {
            const { publicKey: firstKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
            const firstJwk = JWK.export(firstKey);
            firstJwk.kid = 'first';

            const { publicKey: secondKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
            const secondJwk = JWK.export(secondKey);
            secondJwk.kid = 'second';

            const fetchMock = vi.fn(async () => ({
                ok: true,
                status: 200,
                statusText: 'OK',
                json: async () => ({ keys: [fetchMock.mock.calls.length === 1 ? firstJwk : secondJwk] })
            }));

            const resolver = await JWKS.fromWeb('https://issuer.example', {
                fetch: fetchMock as unknown as typeof fetch,
                ttl: 0
            });

            await resolver.key('first');
            expect(fetchMock).toHaveBeenCalledTimes(1);

            await resolver.key('first');
            expect(fetchMock).toHaveBeenCalledTimes(1);

            const reloadedKeys = await resolver.reload();
            expect(fetchMock).toHaveBeenCalledTimes(2);
            expect(reloadedKeys[0].kid).toBe('second');
        });

        it('fromWeb throws when initial fetch fails', async () => {
            const fetchMock = vi.fn(async () => ({
                ok: false,
                status: 503,
                statusText: 'Service Unavailable',
                json: async () => ({})
            })) as unknown as typeof fetch;

            await expect(
                JWKS.fromWeb('https://issuer.example', { fetch: fetchMock })
            ).rejects.toThrow('Failed to fetch JWKS: 503 Service Unavailable');
        });

        it('fromWeb throws when fetched payload is not a valid JWKS', async () => {
            const fetchMock = vi.fn(async () => ({
                ok: true,
                status: 200,
                statusText: 'OK',
                json: async () => ({ invalid: true })
            })) as unknown as typeof fetch;

            await expect(
                JWKS.fromWeb('https://issuer.example', { fetch: fetchMock })
            ).rejects.toThrow('Invalid JWKS');
        });

        it('fromWeb times out initial preload fetch', async () => {
            const fetchMock = vi.fn((_input: string | URL | Request, init?: RequestInit) =>
                new Promise<Response>((_resolve, reject) => {
                    init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
                })
            ) as unknown as typeof fetch;

            await expect(
                JWKS.fromWeb('https://issuer.example', { fetch: fetchMock, timeoutMs: 10 })
            ).rejects.toThrow('JWKS fetch timed out after 10ms');
        });

        it('fromWeb throws when no fetch implementation is available', async () => {
            vi.stubGlobal('fetch', undefined as any);

            try {
                await expect(
                    JWKS.fromWeb('https://issuer.example', { fetch: undefined as any })
                ).rejects.toThrow('No fetch implementation available');
            } finally {
                vi.unstubAllGlobals();
            }
        });

        it('fromWeb find returns matching keys and findFirst returns first match', async () => {
            const { publicKey: rsaPublicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
            const rsaJwk = JWK.export(rsaPublicKey);
            rsaJwk.kid = 'rsa-key';
            rsaJwk.use = 'sig';

            const { publicKey: ecPublicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
            const ecJwk = JWK.export(ecPublicKey);
            ecJwk.kid = 'ec-key';
            ecJwk.use = 'sig';

            const fetchMock = vi.fn(async () => ({
                ok: true,
                status: 200,
                statusText: 'OK',
                json: async () => ({ keys: [rsaJwk, ecJwk] })
            })) as unknown as typeof fetch;

            const resolver = await JWKS.fromWeb('https://issuer.example', { fetch: fetchMock });

            const matches = await resolver.find({ use: 'sig', kty: 'RSA' });
            expect(matches).toHaveLength(1);
            expect(matches[0].kid).toBe('rsa-key');

            const first = await resolver.findFirst({ use: 'sig', kty: 'EC' });
            expect(first.kid).toBe('ec-key');
        });

        it('fromWeb key returns by kid, export returns cached jwks, and find supports array fields', async () => {
            const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
            const jwk = JWK.export(publicKey);
            jwk.kid = 'ops-key';
            jwk.key_ops = ['verify'];

            const fetchMock = vi.fn(async () => ({
                ok: true,
                status: 200,
                statusText: 'OK',
                json: async () => ({ keys: [jwk] })
            })) as unknown as typeof fetch;

            const resolver = await JWKS.fromWeb('https://issuer.example', { fetch: fetchMock });

            const keyByKid = await resolver.key('ops-key');
            expect(keyByKid?.kid).toBe('ops-key');

            const foundByOps = await resolver.find({ key_ops: ['verify'] });
            expect(foundByOps).toHaveLength(1);
            expect(foundByOps[0].kid).toBe('ops-key');

            const notFoundByOps = await resolver.find({ key_ops: ['sign'] });
            expect(notFoundByOps).toHaveLength(0);

            const allKeys = await resolver.find({});
            expect(allKeys).toHaveLength(1);

            const exported = resolver.export();
            expect(exported?.keys).toHaveLength(1);
            expect(exported?.keys[0].kid).toBe('ops-key');
        });

        it('fromWeb uses provided cache value before fetching', async () => {
            const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
            const jwk = JWK.export(publicKey);
            jwk.kid = 'cached';

            const fetchMock = vi.fn(async () => {
                throw new Error('fetch should not be called');
            }) as unknown as typeof fetch;

            const cache = {
                get: vi.fn(async () => ({ keys: [jwk] })),
                set: vi.fn(async () => undefined)
            };

            const resolver = await JWKS.fromWeb('https://issuer.example', {
                fetch: fetchMock,
                cache,
                ttl: 1000
            });

            const key = await resolver.key('cached');
            expect(key?.kty).toBe('RSA');
            expect(fetchMock).not.toHaveBeenCalled();
            expect(cache.get).toHaveBeenCalledTimes(1);
        });

        it('fromWeb refreshes on resolver call when ttl expires', async () => {
            const { publicKey: firstKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
            const firstJwk = JWK.export(firstKey);
            firstJwk.kid = 'first';

            const { publicKey: secondKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
            const secondJwk = JWK.export(secondKey);
            secondJwk.kid = 'second';

            const fetchMock = vi.fn(async () => ({
                ok: true,
                status: 200,
                statusText: 'OK',
                json: async () => ({ keys: [fetchMock.mock.calls.length === 1 ? firstJwk : secondJwk] })
            }));

            const resolver = await JWKS.fromWeb('https://issuer.example', {
                fetch: fetchMock as unknown as typeof fetch,
                ttl: 1
            });

            await new Promise(resolve => setTimeout(resolve, 5));
            await resolver.key('second');
            expect(fetchMock).toHaveBeenCalledTimes(2);
        });

        it('fromWeb refreshes on list call when ttl expires', async () => {
            const { publicKey: firstKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
            const firstJwk = JWK.export(firstKey);
            firstJwk.kid = 'first';

            const { publicKey: secondKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
            const secondJwk = JWK.export(secondKey);
            secondJwk.kid = 'second';

            const fetchMock = vi.fn(async () => ({
                ok: true,
                status: 200,
                statusText: 'OK',
                json: async () => ({ keys: [fetchMock.mock.calls.length === 1 ? firstJwk : secondJwk] })
            }))

            const resolver = await JWKS.fromWeb('https://issuer.example', {
                fetch: fetchMock as unknown as typeof fetch,
                ttl: 1
            });

            await new Promise(resolve => setTimeout(resolve, 5));
            const keys = await resolver.list();
            expect(fetchMock).toHaveBeenCalledTimes(2);
            expect(keys[0].kid).toBe('second');
        });

        it('fromWeb keeps stale keys and warns when refresh fails after cache warmup', async () => {
            const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
            const jwk = JWK.export(publicKey);
            jwk.kid = 'stable';

            const fetchMock = vi.fn(async () => {
                if (fetchMock.mock.calls.length === 1) {
                    return {
                        ok: true,
                        status: 200,
                        statusText: 'OK',
                        json: async () => ({ keys: [jwk] })
                    };
                }
                throw new Error('temporary network failure');
            })

            const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

            try {
                const resolver = await JWKS.fromWeb('https://issuer.example', {
                    fetch: fetchMock as unknown as typeof fetch,
                    ttl: 1
                });

                await new Promise(resolve => setTimeout(resolve, 5));
                const key = await resolver.key('stable');

                expect(key?.kty).toBe('RSA');
                expect(fetchMock).toHaveBeenCalledTimes(2);
                expect(warnSpy).toHaveBeenCalledTimes(1);
            } finally {
                warnSpy.mockRestore();
            }
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

        it('throws on invalid KeyObject for toPublic', () => {
            expect(() => JWK.toPublic(null as unknown as KeyObject))
                .toThrow('Invalid KeyObject');
        });
    });

});
