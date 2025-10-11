import {
    createHmac,
    createSign,
    createVerify,
    type BinaryLike,
    type KeyLike
} from 'crypto';

// Base64URL helpers (padding-safe)
export const base64Url = {
    encode: (input: string | Buffer): string =>
        Buffer.from(input).toString('base64url'),

    decode: (input: string): string => {
        // Node.js Buffer handles unpadded base64url since v16, but we normalize for safety
        return Buffer.from(input, 'base64url').toString();
    }
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

// Signature algorithms
export const SignatureAlgorithm = {
    // HMAC
    HS256: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createHmac('sha256', secret).update(data).digest('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) =>
            createHmac('sha256', secret).update(data).digest('base64url') === signature
    },
    HS384: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createHmac('sha384', secret).update(data).digest('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) =>
            createHmac('sha384', secret).update(data).digest('base64url') === signature
    },
    HS512: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createHmac('sha512', secret).update(data).digest('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) =>
            createHmac('sha512', secret).update(data).digest('base64url') === signature
    },

    // RSA (DER-encoded signatures, base64url)
    RS256: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createSign('RSA-SHA256').update(data).end().sign(secret).toString('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) =>
            createVerify('RSA-SHA256')
                .update(data)
                .end()
                .verify(secret, Buffer.from(signature, 'base64url'))
    },
    RS384: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createSign('RSA-SHA384').update(data).end().sign(secret).toString('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) =>
            createVerify('RSA-SHA384')
                .update(data)
                .end()
                .verify(secret, Buffer.from(signature, 'base64url'))
    },
    RS512: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createSign('RSA-SHA512').update(data).end().sign(secret).toString('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) =>
            createVerify('RSA-SHA512')
                .update(data)
                .end()
                .verify(secret, Buffer.from(signature, 'base64url'))
    },

    // ECDSA (DER-encoded by default — no dsaEncoding!)
    ES256: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createSign('SHA256').update(data).end().sign(secret).toString('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) =>
            createVerify('SHA256')
                .update(data)
                .end()
                .verify(secret, Buffer.from(signature, 'base64url'))
    },
    ES384: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createSign('SHA384').update(data).end().sign(secret).toString('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) =>
            createVerify('SHA384')
                .update(data)
                .end()
                .verify(secret, Buffer.from(signature, 'base64url'))
    },
    ES512: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createSign('SHA512').update(data).end().sign(secret).toString('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) =>
            createVerify('SHA512')
                .update(data)
                .end()
                .verify(secret, Buffer.from(signature, 'base64url'))
    }
} as const;

export type SupportedAlgorithm = keyof typeof SignatureAlgorithm;

export const SupportedAlgorithms = Object.keys(SignatureAlgorithm) as Array<SupportedAlgorithm>;

/**
 * Decode a JWT string into its parts (without verification)
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

    try {
        const header = JSON.parse(base64Url.decode(headerPart)) as JWTHeader;
        const payload = JSON.parse(base64Url.decode(payloadPart)) as JWTPayload;
        return { header, payload, signature };
    } catch (err) {
        throw new Error(`Invalid JWT: malformed header or payload (${(err as Error).message})`);
    }
};

/**
 * Sign a JWT
 */
export const sign = (
    payload: JWTPayload,
    secret: KeyLike,
    options: {
        alg?: SupportedAlgorithm;
        kid?: string;
        typ?: string;
    } = {}
): string => {
    const alg = options.alg ?? 'HS256';
    const typ = options.typ ?? 'JWT';

    if (!(alg in SignatureAlgorithm)) {
        throw new Error(`Unsupported algorithm: ${alg}`);
    }

    const header: JWTHeader = { alg, typ };
    if (options.kid) header.kid = options.kid;

    const headerEncoded = base64Url.encode(JSON.stringify(header));
    const payloadEncoded = base64Url.encode(JSON.stringify(payload));

    const signingInput = `${headerEncoded}.${payloadEncoded}`;
    const signature = SignatureAlgorithm[alg].sign(signingInput, secret);

    return `${headerEncoded}.${payloadEncoded}.${signature}`;
};

/**
 * Verify and validate a JWT
 */
export const verify = (
    token: string,
    secret: KeyLike,
    options: {
        ignoreExpiration?: boolean;
        clockSkew?: number; // in seconds, default 0
    } = {}
):
    | { valid: true; header: JWTHeader; payload: JWTPayload; signature: string }
    | { valid: false; error: { reason: string; code: string } } => {
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

    const { header, payload, signature } = decoded;

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

    // Optional: validate 'typ' header
    if (header.typ && header.typ !== 'JWT') {
        return {
            valid: false,
            error: {
                reason: `Invalid token type: expected 'JWT', got '${header.typ}'`,
                code: 'INVALID_TYPE'
            }
        };
    }

    // Verify signature
    const signingInput = `${base64Url.encode(JSON.stringify(header))}.${base64Url.encode(JSON.stringify(payload))}`;
    const isValidSignature = SignatureAlgorithm[alg].verify(signingInput, secret, signature);

    if (!isValidSignature) {
        return {
            valid: false,
            error: {
                reason: "Signature verification failed",
                code: 'INVALID_SIGNATURE'
            }
        };
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

    return { valid: true, header, payload, signature };
};

// Optional: namespace export (not default)
export const JWT = {
    sign,
    verify,
    decode,
    algorithms: SignatureAlgorithm
};
