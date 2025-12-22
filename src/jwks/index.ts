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

export const JWKS = {
    toKeyObject: JWKSToKeyObject,
    normalize: normalizeJWKS
}
