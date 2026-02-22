import {
    createPrivateKey,
    createPublicKey,
    createSecretKey,
    createHash,
    type KeyObject
} from 'crypto';

// JWK Types
export type JWK =
    | RSAJWK
    | ECJWK
    | OKPJWK
    | OctJWK;

interface BaseJWK {
    kty: string;
    kid?: string;
    alg?: string;
    use?: 'sig' | 'enc';
    key_ops?: Array<'sign' | 'verify'>;
    x5c?: string[]; // X.509 cert chain
    x5t?: string;   // Base64url thumbprint
}

export interface RSAJWK extends BaseJWK {
    kty: 'RSA';
    n: string;
    e: string;
    d?: string;
    p?: string;
    q?: string;
    dp?: string;
    dq?: string;
    qi?: string;
}

export interface ECJWK extends BaseJWK {
    kty: 'EC';
    crv: 'P-256' | 'P-384' | 'P-521' | 'secp256k1';
    x: string;
    y: string;
    d?: string;
}

export interface OKPJWK extends BaseJWK {
    kty: 'OKP';
    crv: 'Ed25519';
    x: string;
    d?: string;
}

export interface OctJWK extends BaseJWK {
    kty: 'oct';
    k: string;
}

/**
 * Export KeyObject to JWK
 * @param key
 */
export function exportJWK(key: KeyObject): JWK {
    if (!key || typeof key !== 'object') throw new Error('Invalid KeyObject');
    return key.export({format: 'jwk'}) as JWK;
}

/**
 * Import JWK to KeyObject
 * @param jwk
 */
export function importJWK(jwk: JWK): KeyObject {
    if (!jwk || typeof jwk !== 'object') throw new Error('Invalid JWK');

    switch (jwk.kty) {
        case 'oct': {
            if (!('k' in jwk) || typeof jwk.k !== 'string') {
                throw new Error('Invalid oct JWK: missing "k"');
            }

            return createSecretKey(Buffer.from(jwk.k, 'base64url'));
        }

        case 'RSA':
        case 'EC':
        case 'OKP': {
            // private key
            if ('d' in jwk && typeof (jwk as any).d === 'string') {
                // @ts-ignore
                return createPrivateKey({format: 'jwk', key: jwk});
            }

            // public key
            // @ts-ignore
            return createPublicKey({format: 'jwk', key: jwk});
        }

        default:
            throw new Error(`Unsupported JWK key type: ${(jwk as any).kty}`);
    }
}

/**
 * Export public-only JWK
 * @param key
 */
export function toPublicJWK(key: KeyObject): JWK {
    if (!key || typeof key !== 'object') {
        throw new Error('Invalid KeyObject');
    }

    const publicKey =
        key.type === 'private'
            ? createPublicKey(key)
            : key;

    const jwk = publicKey.export({format: 'jwk'}) as JWK;

    // Ensure private fields are not present
    delete (jwk as any).d;
    delete (jwk as any).p;
    delete (jwk as any).q;
    delete (jwk as any).dp;
    delete (jwk as any).dq;
    delete (jwk as any).qi;
    return jwk;
}

/**
 * RFC 7638 JWK thumbprint
 * @param jwk
 * @param hashAlg
 */
export function getJWKThumbprint(jwk: JWK, hashAlg: 'sha256' = 'sha256'): string {
    if (!jwk || typeof jwk !== 'object') {
        throw new Error('Invalid JWK');
    }

    let fields: Record<string, string>;

    switch (jwk.kty) {
        case 'RSA':
            fields = {e: jwk.e, kty: jwk.kty, n: jwk.n};
            break;

        case 'EC':
            fields = {crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y};
            break;

        case 'OKP':
            fields = {crv: jwk.crv, kty: jwk.kty, x: jwk.x};
            break;

        case 'oct':
            fields = {k: jwk.k, kty: jwk.kty};
            break;

        default:
            throw new Error(`Unsupported JWK key type: ${(jwk as any).kty}`);
    }

    // Lexicographically sorted JSON
    const json = JSON.stringify(
        Object.keys(fields)
            .sort()
            .reduce((acc, k) => {
                acc[k] = fields[k];
                return acc;
            }, {} as Record<string, string>)
    );

    return createHash(hashAlg)
        .update(json)
        .digest('base64url');
}


/**
 * Compute x5t (SHA-1) from first cert in x5c if not set
 * @param jwk
 */
export function computeX5T(jwk: JWK): string | undefined {
    if (!jwk.x5c?.length) return undefined;
    return createHash('sha1').update(Buffer.from(jwk.x5c[0], 'base64')).digest('base64url');
}

export const JWK = {
    export: exportJWK,
    import: importJWK,
    toPublic: toPublicJWK,
    thumbprint: getJWKThumbprint,
}

export interface JWKS {
    keys: JWK[];
}

/**
 * Convert JWKS specific key of first key to KeyObject
 * @param jwks
 * @param kid
 * @constructor
 */
export function JWKSToKeyObject(
    jwks: JWKS,
    kid?: string
): KeyObject {
    if (!jwks || !Array.isArray(jwks.keys)) throw new Error('Invalid JWKS');

    let jwk: JWK | undefined;

    if (kid) jwk = jwks.keys.find(k => k.kid === kid);

    // Fallback: single-key JWKS
    if (!jwk && jwks.keys.length === 1) jwk = jwks.keys[0];

    if (!jwk) throw new Error('Key not found in JWKS');
    return importJWK(jwk);
}

/**
 * Normalize JWKS
 * @param jwks
 */
export function normalizeJWKS(jwks: JWKS): JWKS {
    return {
        keys: jwks.keys.map(jwk => ({
            ...jwk,
            kid: jwk.kid ?? getJWKThumbprint(jwk),
            x5t: jwk.x5t ?? computeX5T(jwk)
        }))
    };
}

export const fromWeb = async (
    url: string | URL,
    options: Partial<{
        fetch: typeof fetch;
        ttl: number;
        timeoutMs: number;
        endpointOverride: string;
        overrideEndpointCheck: boolean;
        cache: {
            get: (key: string) => JWKS | undefined | Promise<JWKS | undefined>;
            set: (key: string, value: JWKS) => void | Promise<void>;
        };
    }> = {}
) => {
    const baseUrl = typeof url === 'string' ? url : url.toString();
    const fetchFn = options.fetch ?? globalThis.fetch;
    const ttl = Math.max(0, options.ttl ?? 5 * 60_000);
    const timeoutMs = Math.max(0, options.timeoutMs ?? 5_000);
    const wellKnownPath = '/.well-known/jwks.json';

    if (!fetchFn) {
        throw new Error('No fetch implementation available');
    }

    const endpoint = (() => {
        if (options.endpointOverride) {
            const override = options.endpointOverride;
            try {
                return new URL(override, baseUrl).toString();
            } catch {
                return override;
            }
        }

        if (options.overrideEndpointCheck) {
            return baseUrl;
        }

        if (baseUrl.endsWith(wellKnownPath)) {
            return baseUrl;
        }

        return `${baseUrl.replace(/\/+$/, '')}${wellKnownPath}`;
    })();

    const cache = (() => {
        if (options.cache) return options.cache;
        let memoryValue: JWKS | undefined;
        return {
            get: () => memoryValue,
            set: (_key: string, value: JWKS) => {
                memoryValue = value;
            }
        };
    })();

    let cachedJWKS: JWKS | undefined;
    let nextRefreshAt = 0;
    let refreshInFlight: Promise<JWKS> | undefined;
    let consecutiveFailures = 0;

    const fetchJWKS = async (allowStaleOnFailure: boolean): Promise<JWKS> => {
        if (refreshInFlight) return refreshInFlight;

        refreshInFlight = (async () => {
            const controller = new AbortController();
            let timeoutHandle: ReturnType<typeof setTimeout> | undefined;

            if (timeoutMs > 0) {
                timeoutHandle = setTimeout(() => controller.abort(), timeoutMs);
            }

            let response: Response;
            try {
                response = await fetchFn(endpoint, {signal: controller.signal});
            } catch (error) {
                if (controller.signal.aborted) {
                    throw new Error(`JWKS fetch timed out after ${timeoutMs}ms`);
                }
                throw error;
            } finally {
                if (timeoutHandle) clearTimeout(timeoutHandle);
            }

            if (!response.ok) {
                throw new Error(`Failed to fetch JWKS: ${response.status} ${response.statusText}`);
            }

            const body = await response.json();
            if (!body || typeof body !== 'object' || !Array.isArray((body as any).keys)) {
                throw new Error('Invalid JWKS');
            }

            return normalizeJWKS(body as JWKS);
        })();

        try {
            const fresh = await refreshInFlight;
            cachedJWKS = fresh;
            await cache.set(endpoint, fresh);
            consecutiveFailures = 0;
            if (ttl > 0) nextRefreshAt = Date.now() + ttl;
            return fresh;
        } catch (error) {
            if (!allowStaleOnFailure || !cachedJWKS) {
                throw error;
            }

            consecutiveFailures += 1;
            if (ttl > 0) {
                const backoff = Math.min(
                    Math.max(ttl, 30_000) * Math.pow(2, consecutiveFailures - 1),
                    15 * 60_000
                );
                nextRefreshAt = Date.now() + backoff;
            }
            console.warn(`JWKS refresh failed for "${endpoint}", using stale cache.`, error);
            return cachedJWKS;
        } finally {
            refreshInFlight = undefined;
        }
    };

    cachedJWKS = await cache.get(endpoint);
    if (!cachedJWKS) {
        cachedJWKS = await fetchJWKS(false);
    } else {
        cachedJWKS = normalizeJWKS(cachedJWKS);
        if (ttl > 0) nextRefreshAt = Date.now() + ttl;
    }


    return ({
        async list(): Promise<JWK[]> {
            if (ttl > 0 && Date.now() >= nextRefreshAt) {
                await fetchJWKS(true);
            }
            return Promise.resolve((cachedJWKS as JWKS).keys);
        },
        async refresh(): Promise<JWK[]> {
            await fetchJWKS(false);
            return (cachedJWKS as JWKS).keys;
        },
        async key(kid: string) {
            const keys = await this.list();
            return keys.find((v) => v.kid === kid);
        },
        async find(input: Partial<BaseJWK>): Promise<JWK[]> {
            const keys = await this.list();
            const entries = Object.entries(input) as Array<[keyof BaseJWK, BaseJWK[keyof BaseJWK]]>;

            if (entries.length === 0) return keys;

            return keys.filter((key) =>
                entries.every(([field, expected]) => {
                    const value = key[field];
                    if (Array.isArray(expected)) {
                        return Array.isArray(value)
                            && value.length === expected.length
                            && value.every((item, i) => item === expected[i]);
                    }
                    return value === expected;
                })
            );
        },
        async findFirst(input: Partial<BaseJWK>): Promise<JWK> {
            return this.find(input).then(([key]) => key);
        },
        export(): JWKS | undefined {
            return cachedJWKS;
        }
    });
}

export const JWKS = {
    toKeyObject: JWKSToKeyObject,
    normalize: normalizeJWKS,
    fromWeb
}
