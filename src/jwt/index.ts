import crypto, {
    createHmac,
    createSign,
    createVerify,
    createPrivateKey,
    createSecretKey,
    sign as cryptoSign,
    verify as cryptoVerify,
    timingSafeEqual,
    type BinaryLike,
    type KeyLike,
    type KeyObject
} from 'crypto';

// Base64URL helpers (padding-safe)
export const base64Url = {
    encode: (input: string | Buffer): string => Buffer.from(input).toString('base64url'),
    decode: (input: string): string => Buffer.from(input, 'base64url').toString()
};

/**
 * Timing-safe string comparison to prevent timing attacks
 * @param a
 * @param b
 */
const timingSafeCompare = (a: string, b: string): boolean => {
    if (a.length !== b.length) {
        return false;
    }
    return timingSafeEqual(Buffer.from(a), Buffer.from(b));
};

// Standard JWT payload claims
export interface JWTPayload {
    /**
     * Issuer
     */
    iss?: string;
    /**
     * Subject
     */
    sub?: string;
    /**
     * Audience
     */
    aud?: string | string[];
    /**
     * Expiration Time (as UNIX timestamp)
     */
    exp?: number;
    /**
     * Not Before (as UNIX timestamp)
     */
    nbf?: number;
    /**
     * Issued At (as UNIX timestamp)
     */
    iat?: number;
    /**
     * JWT ID
     */
    jti?: string;
    /**
     * Session ID
     */
    sid?: string;

    /**
     * Custom claims
     */
    [key: string]: unknown;
}

export interface JWTHeader {
    alg: string; // Allow unknown algs during decode
    typ?: string;
    kid?: string;
}

export interface JWT {
    header: JWTHeader;
    payload: JWTPayload;
    signature: string;
}

const BASE64URL_SEGMENT_REGEX = /^[A-Za-z0-9_-]+$/;

function isPlainObject(input: unknown): input is Record<string, unknown> {
    return typeof input === 'object' && input !== null && !Array.isArray(input);
}

function isFiniteNumber(input: unknown): input is number {
    return typeof input === 'number' && Number.isFinite(input);
}

function isStringArray(input: unknown): input is string[] {
    return Array.isArray(input) && input.every((value) => typeof value === 'string');
}

function validateRegisteredClaims(payload: JWTPayload): { reason: string; code: string } | null {
    const claimValidators: Array<{ claim: keyof JWTPayload; valid: boolean; expected: string }> = [
        {claim: 'iss', valid: payload.iss === undefined || typeof payload.iss === 'string', expected: 'string'},
        {claim: 'sub', valid: payload.sub === undefined || typeof payload.sub === 'string', expected: 'string'},
        {claim: 'jti', valid: payload.jti === undefined || typeof payload.jti === 'string', expected: 'string'},
        {claim: 'sid', valid: payload.sid === undefined || typeof payload.sid === 'string', expected: 'string'},
        {claim: 'iat', valid: payload.iat === undefined || isFiniteNumber(payload.iat), expected: 'number'},
        {claim: 'exp', valid: payload.exp === undefined || isFiniteNumber(payload.exp), expected: 'number'},
        {claim: 'nbf', valid: payload.nbf === undefined || isFiniteNumber(payload.nbf), expected: 'number'},
    ];

    for (const entry of claimValidators) {
        if (!entry.valid) {
            return {
                reason: `Invalid "${entry.claim}" claim: expected ${entry.expected}`,
                code: 'INVALID_CLAIM'
            };
        }
    }

    if (payload.aud !== undefined) {
        const isValidAudience = typeof payload.aud === 'string' || isStringArray(payload.aud);
        if (!isValidAudience) {
            return {
                reason: 'Invalid "aud" claim: expected string or string[]',
                code: 'INVALID_CLAIM'
            };
        }
    }

    return null;
}

function validateVerifyOptions(options: VerifyOptions): { reason: string; code: string } | null {
    if (options.signatureFormat !== undefined && options.signatureFormat !== 'der' && options.signatureFormat !== 'jose') {
        return {
            reason: 'Invalid signatureFormat option: expected "der" or "jose"',
            code: 'INVALID_OPTIONS'
        };
    }

    if (options.clockSkew !== undefined && (!isFiniteNumber(options.clockSkew) || options.clockSkew < 0)) {
        return {
            reason: 'Invalid clockSkew option: expected a non-negative finite number',
            code: 'INVALID_OPTIONS'
        };
    }

    if (options.maxTokenAge !== undefined && (!isFiniteNumber(options.maxTokenAge) || options.maxTokenAge < 0)) {
        return {
            reason: 'Invalid maxTokenAge option: expected a non-negative finite number',
            code: 'INVALID_OPTIONS'
        };
    }

    if (options.issuer !== undefined && typeof options.issuer !== 'string') {
        return {
            reason: 'Invalid issuer option: expected string',
            code: 'INVALID_OPTIONS'
        };
    }

    if (options.subject !== undefined && typeof options.subject !== 'string') {
        return {
            reason: 'Invalid subject option: expected string',
            code: 'INVALID_OPTIONS'
        };
    }

    if (options.jwtId !== undefined && typeof options.jwtId !== 'string') {
        return {
            reason: 'Invalid jwtId option: expected string',
            code: 'INVALID_OPTIONS'
        };
    }

    if (options.audience !== undefined) {
        const isValidAudience = typeof options.audience === 'string' || isStringArray(options.audience);
        if (!isValidAudience) {
            return {
                reason: 'Invalid audience option: expected string or string[]',
                code: 'INVALID_OPTIONS'
            };
        }
    }

    if (options.algorithms !== undefined) {
        if (!Array.isArray(options.algorithms)) {
            return {
                reason: 'Invalid algorithms option: expected an array',
                code: 'INVALID_OPTIONS'
            };
        }

        const invalidAlgorithm = options.algorithms.find((alg) => !(alg in SignatureAlgorithm));
        if (invalidAlgorithm) {
            return {
                reason: `Invalid algorithms option: unsupported algorithm "${invalidAlgorithm}"`,
                code: 'INVALID_OPTIONS'
            };
        }
    }

    return null;
}


//JOSE-helpers
function joseLenForAlg(alg: string): number {
    switch (alg) {
        case 'ES256':
        case 'ES256K':
            return 64;  // 32 + 32
        case 'ES384':
            return 96;  // 48 + 48
        case 'ES512':
            return 132; // 66 + 66 (P-521)
        /* c8 ignore next 2 */
        default:
            throw new Error(`Unsupported ECDSA alg for JOSE conversion: ${alg}`);
    }
}

function derToJose(der: Buffer, outLen: number): Buffer {
    let i = 0;
    if (der[i++] !== 0x30) throw new Error('Invalid DER ECDSA signature');

    // seq length (short/long form)
    let seqLen = der[i++];
    if (seqLen & 0x80) {
        const n = seqLen & 0x7f;
        seqLen = 0;
        for (let k = 0; k < n; k++) seqLen = (seqLen << 8) | der[i++];
    }

    if (der[i++] !== 0x02) throw new Error('Invalid DER ECDSA signature (r)');
    const rLen = der[i++];
    let r = der.subarray(i, i + rLen);
    i += rLen;

    if (der[i++] !== 0x02) throw new Error('Invalid DER ECDSA signature (s)');
    const sLen = der[i++];
    let s = der.subarray(i, i + sLen);

    // strip leading zeros
    while (r.length > outLen / 2 && r[0] === 0x00) r = r.subarray(1);
    while (s.length > outLen / 2 && s[0] === 0x00) s = s.subarray(1);

    const rPad = Buffer.concat([Buffer.alloc(outLen / 2 - r.length, 0), r]);
    const sPad = Buffer.concat([Buffer.alloc(outLen / 2 - s.length, 0), s]);
    return Buffer.concat([rPad, sPad]);
}

function joseToDer(jose: Buffer): Buffer {
    const half = jose.length / 2;
    let r = jose.subarray(0, half);
    let s = jose.subarray(half);

    // trim leading zeros
    while (r.length > 1 && r[0] === 0x00 && (r[1] & 0x80) === 0) r = r.subarray(1);
    while (s.length > 1 && s[0] === 0x00 && (s[1] & 0x80) === 0) s = s.subarray(1);

    // if high bit set, prepend 0x00
    if (r[0] & 0x80) r = Buffer.concat([Buffer.from([0x00]), r]);
    if (s[0] & 0x80) s = Buffer.concat([Buffer.from([0x00]), s]);

    const rPart = Buffer.concat([Buffer.from([0x02, r.length]), r]);
    const sPart = Buffer.concat([Buffer.from([0x02, s.length]), s]);

    const seqLen = rPart.length + sPart.length;

    let lenBytes: Buffer;
    if (seqLen < 0x80) {
        lenBytes = Buffer.from([seqLen]);
    } else {
        const tmp: number[] = [];
        let n = seqLen;
        while (n > 0) {
            tmp.unshift(n & 0xff);
            n >>= 8;
        }
        lenBytes = Buffer.from([0x80 | tmp.length, ...tmp]);
    }

    return Buffer.concat([Buffer.from([0x30]), lenBytes, rPart, sPart]);
}

function isEcdsaAlg(alg: string): boolean {
    return alg === 'ES256' || alg === 'ES384' || alg === 'ES512' || alg === 'ES256K';
}

type SignatureAlgorithmImplementation = {
    sign: (data: BinaryLike, secret: KeyLike) => string;
    verify: (data: BinaryLike, secret: KeyLike, signature: string) => boolean;
};

type SignatureAlgorithmsMap = {
    HS256: SignatureAlgorithmImplementation;
    HS384: SignatureAlgorithmImplementation;
    HS512: SignatureAlgorithmImplementation;
    RS256: SignatureAlgorithmImplementation;
    RS384: SignatureAlgorithmImplementation;
    RS512: SignatureAlgorithmImplementation;
    ES256: SignatureAlgorithmImplementation;
    ES384: SignatureAlgorithmImplementation;
    ES512: SignatureAlgorithmImplementation;
    ES256K: SignatureAlgorithmImplementation;
    PS256: SignatureAlgorithmImplementation;
    PS384: SignatureAlgorithmImplementation;
    PS512: SignatureAlgorithmImplementation;
    EdDSA: SignatureAlgorithmImplementation;
};

const createHmacAlgorithm = (algorithm: string): SignatureAlgorithmImplementation => ({
    sign: (data: BinaryLike, secret: KeyLike): string =>
        createHmac(algorithm, secret).update(data).digest('base64url'),
    verify: (data: BinaryLike, secret: KeyLike, signature: string): boolean => {
        const expected = createHmac(algorithm, secret).update(data).digest('base64url');
        return timingSafeCompare(expected, signature);
    }
});

const createVerifyAlgorithm = (algorithm: string): SignatureAlgorithmImplementation => ({
    sign: (data: BinaryLike, secret: KeyLike): string =>
        createSign(algorithm).update(data).end().sign(secret).toString('base64url'),
    verify: (data: BinaryLike, secret: KeyLike, signature: string): boolean => {
        try {
            return createVerify(algorithm)
                .update(data)
                .end()
                .verify(secret, Buffer.from(signature, 'base64url'));
        } catch {
            return false;
        }
    }
});

const createPssAlgorithm = (algorithm: string, saltLength: number): SignatureAlgorithmImplementation => ({
    sign: (data: BinaryLike, secret: KeyLike): string =>
        createSign(algorithm)
            .update(data)
            .end()
            .sign({
                //@ts-ignore
                key: secret,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength
            })
            .toString('base64url'),
    verify: (data: BinaryLike, secret: KeyLike, signature: string): boolean => {
        try {
            return createVerify(algorithm)
                .update(data)
                .end()
                .verify({
                    //@ts-ignore
                    key: secret,
                    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                    saltLength
                }, Buffer.from(signature, 'base64url'));
        } catch {
            return false;
        }
    }
});

const edDsaAlgorithm: SignatureAlgorithmImplementation = {
    sign: (data: BinaryLike, secret: KeyLike): string =>
        cryptoSign(null, typeof data === 'string' ? Buffer.from(data, 'utf8') : data, secret)
            .toString('base64url'),
    verify: (data: BinaryLike, secret: KeyLike, signature: string): boolean => {
        try {
            return cryptoVerify(
                null,
                typeof data === 'string' ? Buffer.from(data, 'utf8') : data,
                secret,
                Buffer.from(signature, 'base64url')
            );
        } catch {
            return false;
        }
    }
};


// Signature algorithms
export const SignatureAlgorithm: SignatureAlgorithmsMap = {
    // HMAC
    HS256: createHmacAlgorithm('sha256'),
    HS384: createHmacAlgorithm('sha384'),
    HS512: createHmacAlgorithm('sha512'),

    // RSA (DER-encoded signatures, base64url)
    RS256: createVerifyAlgorithm('RSA-SHA256'),
    RS384: createVerifyAlgorithm('RSA-SHA384'),
    RS512: createVerifyAlgorithm('RSA-SHA512'),

    // ECDSA (DER-encoded by default — no dsaEncoding!)
    ES256: createVerifyAlgorithm('SHA256'),
    ES384: createVerifyAlgorithm('SHA384'),
    ES512: createVerifyAlgorithm('SHA512'),
    ES256K: createVerifyAlgorithm('SHA256'),
    PS256: createPssAlgorithm('RSA-SHA256', 32),
    PS384: createPssAlgorithm('RSA-SHA384', 48),
    PS512: createPssAlgorithm('RSA-SHA512', 64),
    EdDSA: edDsaAlgorithm
} as const;

export type SupportedAlgorithm = keyof typeof SignatureAlgorithm;

export const SupportedAlgorithms = Object.keys(SignatureAlgorithm) as Array<SupportedAlgorithm>;

/**
 * Autodetection of algorithm for KeyObjects
 * @param key
 * @constructor
 */
export function AutodetectAlgorithm(key: KeyObject): SupportedAlgorithm {
    if (key.type === 'secret') return 'HS256';
    if (key.type !== 'private') throw new Error('Only private or symmetric keys can be used to sign JWTs');

    const asymKeyType = key.asymmetricKeyType;
    const details = key.asymmetricKeyDetails;

    switch (asymKeyType) {
        case 'rsa':
            return 'RS256';
        case 'rsa-pss': {
            const hash = details?.hashAlgorithm ?? 'sha256';
            switch (hash) {
                case 'sha256':
                    return 'PS256';
                case 'sha384':
                    return 'PS384';
                case 'sha512':
                    return 'PS512';
                default:
                    throw new Error(`Unsupported RSA-PSS hash algorithm: ${hash}`);
            }
        }
        case 'ec': {
            const curve = details?.namedCurve;
            switch (curve) {
                case 'P-256':
                case 'prime256v1':
                    return 'ES256';
                case 'P-384':
                case 'secp384r1':
                    return 'ES384';
                case 'P-521':
                case 'secp521r1':
                    return 'ES512';
                case 'secp256k1':
                    return 'ES256K';
                default:
                    throw new Error(`Unsupported EC curve: ${curve}`);
            }
        }
        case 'ed25519':
            return 'EdDSA';
        default:
            throw new Error(`Unsupported asymmetric key type: ${asymKeyType}`);
    }
}

/**
 * Normalize KeyLike input to a KeyObject
 * @param key
 */
function toKeyObject(key: KeyLike): KeyObject {
    // Already a KeyObject (private, public, or secret)
    if (typeof key === 'object' && 'type' in key) return key as KeyObject;

    // Try asymmetric private key (PEM / DER / JWK)
    try {
        return createPrivateKey(key);
    } catch {
        // Fallback: symmetric key (HMAC)
        const buffer =
            typeof key === 'string'
                ? Buffer.from(key, 'utf8')
                : Buffer.isBuffer(key)
                    ? key
                    : (() => {
                        throw new Error('Unsupported key type');
                    })();

        return createSecretKey(buffer);
    }
}

/**
 * Decode a JWT string into its parts (without verification)
 * @param token
 */
export const decode = (token: string): JWT => {
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('Invalid JWT: must contain exactly 3 parts separated by "."');
    }

    const [headerPart, payloadPart, signature] = parts;

    if (!headerPart || !payloadPart || !signature) {
        throw new Error('Invalid JWT: empty part detected');
    }

    if (!BASE64URL_SEGMENT_REGEX.test(headerPart) || !BASE64URL_SEGMENT_REGEX.test(payloadPart) || !BASE64URL_SEGMENT_REGEX.test(signature)) {
        throw new Error('Invalid JWT: non-base64url characters detected');
    }

    try {
        const decodedHeader = JSON.parse(base64Url.decode(headerPart));
        const decodedPayload = JSON.parse(base64Url.decode(payloadPart));

        if (!isPlainObject(decodedHeader) || !isPlainObject(decodedPayload)) {
            throw new Error('header and payload must be JSON objects');
        }

        const header = decodedHeader as unknown as JWTHeader;
        const payload = decodedPayload as JWTPayload;

        if (typeof header.alg !== 'string' || header.alg.length === 0) {
            throw new Error('header.alg must be a non-empty string');
        }
        if (header.typ !== undefined && typeof header.typ !== 'string') {
            throw new Error('header.typ must be a string');
        }
        if (header.kid !== undefined && typeof header.kid !== 'string') {
            throw new Error('header.kid must be a string');
        }

        return {header, payload, signature};
    } catch (err) {
        throw new Error(`Invalid JWT: malformed header or payload (${(err as Error).message})`);
    }
}

export type SignOptions = {
    alg?: SupportedAlgorithm;
    kid?: string;
    typ?: string;
    /**
     * default 'der'
     */
    signatureFormat?: 'der' | 'jose';
}

/**
 * Sign a JWT
 * @param payload
 * @param secret
 * @param options
 */
export const sign = (
    payload: JWTPayload,
    secret: KeyLike,
    options: SignOptions = {}
): string => {
    const key = toKeyObject(secret);
    const alg = options.alg ?? AutodetectAlgorithm(key);
    const signatureFormat = options.signatureFormat ?? 'der';
    const typ = options.typ ?? 'JWT';

    if (!(alg in SignatureAlgorithm)) throw new Error(`Unsupported algorithm: ${alg}`);

    const header: JWTHeader = {alg, typ};
    if (options.kid) header.kid = options.kid;

    const headerEncoded = base64Url.encode(JSON.stringify(header));
    const payloadEncoded = base64Url.encode(JSON.stringify(payload));

    const signingInput = `${headerEncoded}.${payloadEncoded}`;

    // existing DER/base64url signature from algorithms
    let signature = SignatureAlgorithm[alg].sign(signingInput, secret);

    // If ES* and caller requested JOSE, convert the DER signature bytes to JOSE bytes
    if (signatureFormat === 'jose' && isEcdsaAlg(alg)) {
        const der = Buffer.from(signature, 'base64url');
        const jose = derToJose(der, joseLenForAlg(alg));
        signature = jose.toString('base64url');
    }

    return `${headerEncoded}.${payloadEncoded}.${signature}`;

};

export type VerifyOptions = {
    algorithms?: SupportedAlgorithm[]; // Whitelist of allowed algorithms
    issuer?: string;
    subject?: string;
    audience?: string | string[];
    jwtId?: string;
    ignoreExpiration?: boolean;
    clockSkew?: number; // in seconds, default 0
    maxTokenAge?: number; // Maximum age in seconds
    signatureFormat?: 'der' | 'jose';
};

/**
 * Verify and validate a JWT
 * @param token
 * @param secret
 * @param options
 */
export const verify = (
    token: string,
    secret: KeyLike,
    options: VerifyOptions  = {}
):
    | { valid: true; header: JWTHeader; payload: JWTPayload; signature: string }
    | { valid: false; error: { reason: string; code: string } } => {
    const invalidOptions = validateVerifyOptions(options);
    if (invalidOptions) {
        return {
            valid: false,
            error: invalidOptions
        };
    }

    let decoded: JWT;
    try {
        decoded = decode(token);
    } catch (err) {
        return {
            valid: false,
            error: {
                reason: (err as Error).message,
                code: 'INVALID_TOKEN'
            }
        };
    }

    const {header, payload, signature} = decoded;
    const invalidClaims = validateRegisteredClaims(payload);
    if (invalidClaims) {
        return {
            valid: false,
            error: invalidClaims
        };
    }

    // Validate algorithm
    const alg = header.alg as SupportedAlgorithm;
    if (!(alg in SignatureAlgorithm)) {
        return {
            valid: false,
            error: {
                reason: `Unsupported or unknown algorithm: ${header.alg}`,
                code: 'INVALID_ALGORITHM'
            }
        };
    }

    // Algorithm whitelist validation (prevents algorithm confusion attacks)
    if (options.algorithms && options.algorithms.length > 0) {
        if (!options.algorithms.includes(alg)) {
            return {
                valid: false,
                error: {
                    reason: `Algorithm "${alg}" is not in the allowed algorithms list`,
                    code: 'ALGORITHM_NOT_ALLOWED'
                }
            };
        }
    }

    // Validate 'typ' header (must be 'JWT' if present)
    if (header.typ !== undefined && header.typ !== 'JWT') {
        return {
            valid: false,
            error: {
                reason: `Invalid token type: expected 'JWT', got '${header.typ}'`,
                code: 'INVALID_TYPE'
            }
        };
    }

    // Verify signature against the exact original JWT signing input.
    const [headerPart, payloadPart] = token.split('.');
    const signingInput = `${headerPart}.${payloadPart}`;

    if (!isEcdsaAlg(alg)) {
        // non-ES* algorithms unchanged
        let isValidSignature = false;
        try {
            isValidSignature = SignatureAlgorithm[alg].verify(signingInput, secret, signature);
        } catch {
            isValidSignature = false;
        }
        if (!isValidSignature) {
            return {valid: false, error: {reason: "Signature verification failed", code: 'INVALID_SIGNATURE'}};
        }
    } else {
        // ES* algorithms: verify DER by default, but allow JOSE + auto-detect
        const format = options.signatureFormat; // undefined means "auto"

        let ok: boolean;

        // 1) If explicitly JOSE -> convert to DER for verification
        if (format === 'jose') {
            try {
                const jose = Buffer.from(signature, 'base64url');
                const derSigB64Url = joseToDer(jose).toString('base64url');
                ok = SignatureAlgorithm[alg].verify(signingInput, secret, derSigB64Url);
            } catch {
                ok = false;
            }
        }
        // 2) If explicitly DER -> verify as-is
        else if (format === 'der') {
            ok = SignatureAlgorithm[alg].verify(signingInput, secret, signature);
        }
        // 3) Auto-detect: try DER first, then JOSE
        else {
            ok = SignatureAlgorithm[alg].verify(signingInput, secret, signature);
            if (!ok) {
                try {
                    const jose = Buffer.from(signature, 'base64url');
                    // quick sanity: only attempt conversion if size matches expected
                    if (jose.length === joseLenForAlg(alg)) {
                        const derSigB64Url = joseToDer(jose).toString('base64url');
                        ok = SignatureAlgorithm[alg].verify(signingInput, secret, derSigB64Url);
                    }
                } catch {
                    // ignore
                }
            }
        }

        if (!ok) {
            return {valid: false, error: {reason: "Signature verification failed", code: 'INVALID_SIGNATURE'}};
        }
    }

    // Time validation
    const now = Math.floor(Date.now() / 1000);
    const skew = options.clockSkew ?? 0;

    if (!options.ignoreExpiration) {
        if (payload.exp !== undefined && now > payload.exp + skew) {
            return {
                valid: false,
                error: {
                    reason: 'Token expired',
                    code: 'TOKEN_EXPIRED'
                }
            };
        }
    }

    if (payload.nbf !== undefined && now + skew < payload.nbf) {
        return {
            valid: false,
            error: {
                reason: 'Token not yet valid',
                code: 'TOKEN_NOT_ACTIVE'
            }
        };
    }

    if (payload.iat !== undefined && now + skew < payload.iat) {
        return {
            valid: false,
            error: {
                reason: 'Token issued in the future',
                code: 'TOKEN_FUTURE_ISSUED'
            }
        };
    }

    // Maximum token age validation
    if (options.maxTokenAge !== undefined && payload.iat !== undefined) {
        const tokenAge = now - payload.iat;
        if (tokenAge > options.maxTokenAge) {
            return {
                valid: false,
                error: {
                    reason: `Token age (${tokenAge}s) exceeds maximum allowed age (${options.maxTokenAge}s)`,
                    code: 'TOKEN_TOO_OLD'
                }
            };
        }
    }

    // --- Claim validations (only if options provided) ---

    // Issuer (`iss`)
    if (options.issuer !== undefined) {
        if (payload.iss === undefined) {
            return {
                valid: false,
                error: {
                    reason: 'Token missing required issuer claim ("iss")',
                    code: 'MISSING_ISSUER'
                }
            };
        }
        if (options.issuer !== payload.iss) {
            return {
                valid: false,
                error: {
                    reason: `Invalid token issuer: expected "${options.issuer}", got "${payload.iss}"`,
                    code: 'INVALID_ISSUER'
                }
            };
        }
    }

    // Subject (`sub`)
    if (options.subject !== undefined) {
        if (payload.sub === undefined) {
            return {
                valid: false,
                error: {
                    reason: 'Token missing required subject claim ("sub")',
                    code: 'MISSING_SUBJECT'
                }
            };
        }
        if (options.subject !== payload.sub) {
            return {
                valid: false,
                error: {
                    reason: `Invalid token subject: expected "${options.subject}", got "${payload.sub}"`,
                    code: 'INVALID_SUBJECT'
                }
            };
        }
    }

    // Audience (`aud`)
    if (options.audience !== undefined) {
        const aud = payload.aud;
        if (aud === undefined) {
            return {
                valid: false,
                error: {
                    reason: 'Token missing required audience claim ("aud")',
                    code: 'MISSING_AUDIENCE'
                }
            };
        }

        const expectedAud = Array.isArray(options.audience) ? options.audience : [options.audience];
        const tokenAud = Array.isArray(aud) ? aud : [aud];

        const hasMatch = expectedAud.some(a => tokenAud.includes(a));
        if (!hasMatch) {
            return {
                valid: false,
                error: {
                    reason: 'Audience claim mismatch',
                    code: 'INVALID_AUDIENCE'
                }
            };
        }
    }

    // JWT ID (`jti`)
    if (options.jwtId !== undefined) {
        if (payload.jti === undefined) {
            return {
                valid: false,
                error: {
                    reason: 'Token missing required JWT ID claim ("jti")',
                    code: 'MISSING_JTI'
                }
            };
        }
        if (options.jwtId !== payload.jti) {
            return {
                valid: false,
                error: {
                    reason: `Invalid JWT ID: expected "${options.jwtId}", got "${payload.jti}"`,
                    code: 'INVALID_JTI'
                }
            };
        }
    }

    return {valid: true, header, payload, signature};
};

//namespace export
export const JWT = {
    sign,
    verify,
    decode,
    algorithms: SignatureAlgorithm
} as const;
