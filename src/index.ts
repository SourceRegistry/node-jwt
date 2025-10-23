import crypto, {
    createHmac,
    createSign,
    createVerify,
    sign as cryptoSign,
    verify as cryptoVerify,
    timingSafeEqual,
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

// Timing-safe string comparison to prevent timing attacks
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

// Signature algorithms
export const SignatureAlgorithm = {
    // HMAC
    HS256: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createHmac('sha256', secret).update(data).digest('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) => {
            const expected = createHmac('sha256', secret).update(data).digest('base64url');
            return timingSafeCompare(expected, signature);
        }
    },
    HS384: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createHmac('sha384', secret).update(data).digest('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) => {
            const expected = createHmac('sha384', secret).update(data).digest('base64url');
            return timingSafeCompare(expected, signature);
        }
    },
    HS512: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createHmac('sha512', secret).update(data).digest('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) => {
            const expected = createHmac('sha512', secret).update(data).digest('base64url');
            return timingSafeCompare(expected, signature);
        }
    },

    // RSA (DER-encoded signatures, base64url)
    RS256: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createSign('RSA-SHA256').update(data).end().sign(secret).toString('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) => {
            try {
                return createVerify('RSA-SHA256')
                    .update(data)
                    .end()
                    .verify(secret, Buffer.from(signature, 'base64url'));
            } catch {
                return false;
            }
        }
    },
    RS384: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createSign('RSA-SHA384').update(data).end().sign(secret).toString('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) => {
            try {
                return createVerify('RSA-SHA384')
                    .update(data)
                    .end()
                    .verify(secret, Buffer.from(signature, 'base64url'));
            } catch {
                return false;
            }
        }
    },
    RS512: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createSign('RSA-SHA512').update(data).end().sign(secret).toString('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) => {
            try {
                return createVerify('RSA-SHA512')
                    .update(data)
                    .end()
                    .verify(secret, Buffer.from(signature, 'base64url'));
            } catch {
                return false;
            }
        }
    },

    // ECDSA (DER-encoded by default — no dsaEncoding!)
    ES256: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createSign('SHA256').update(data).end().sign(secret).toString('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) => {
            try {
                return createVerify('SHA256')
                    .update(data)
                    .end()
                    .verify(secret, Buffer.from(signature, 'base64url'));
            } catch {
                return false;
            }
        }
    },
    ES384: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createSign('SHA384').update(data).end().sign(secret).toString('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) => {
            try {
                return createVerify('SHA384')
                    .update(data)
                    .end()
                    .verify(secret, Buffer.from(signature, 'base64url'));
            } catch {
                return false;
            }
        }
    },
    ES512: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createSign('SHA512').update(data).end().sign(secret).toString('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) => {
            try {
                return createVerify('SHA512')
                    .update(data)
                    .end()
                    .verify(secret, Buffer.from(signature, 'base64url'));
            } catch {
                return false;
            }
        }
    },
    ES256K: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createSign('SHA256').update(data).end().sign(secret).toString('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) => {
            try {
                return createVerify('SHA256')
                    .update(data)
                    .end()
                    .verify(secret, Buffer.from(signature, 'base64url'));
            } catch {
                return false;
            }
        }
    },
    PS256: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createSign('RSA-SHA256')
                .update(data)
                .end()
                .sign({
                    //@ts-ignore
                    key: secret,
                    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                    saltLength: 32
                })
                .toString('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) => {
            try {
                return createVerify('RSA-SHA256')
                    .update(data)
                    .end()
                    .verify({
                        //@ts-ignore
                        key: secret,
                        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                        saltLength: 32
                    }, Buffer.from(signature, 'base64url'));
            } catch {
                return false;
            }
        }
    },
    PS384: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createSign('RSA-SHA384')
                .update(data)
                .end()
                .sign({
                    //@ts-ignore
                    key: secret,
                    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                    saltLength: 48
                })
                .toString('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) => {
            try {
                return createVerify('RSA-SHA384')
                    .update(data)
                    .end()
                    .verify({
                        //@ts-ignore
                        key: secret,
                        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                        saltLength: 48
                    }, Buffer.from(signature, 'base64url'));
            } catch {
                return false;
            }
        }
    },
    PS512: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            createSign('RSA-SHA512')
                .update(data)
                .end()
                .sign({
                    //@ts-ignore
                    key: secret,
                    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                    saltLength: 64
                })
                .toString('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) => {
            try {
                return createVerify('RSA-SHA512')
                    .update(data)
                    .end()
                    .verify({
                        //@ts-ignore
                        key: secret,
                        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                        saltLength: 64
                    }, Buffer.from(signature, 'base64url'));
            } catch {
                return false;
            }
        }
    },
    EdDSA: {
        sign: (data: BinaryLike, secret: KeyLike) =>
            cryptoSign(null, typeof data === 'string' ? Buffer.from(data, 'utf8') : data, secret)
                .toString('base64url'),
        verify: (data: BinaryLike, secret: KeyLike, signature: string) => {
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
        return {header, payload, signature};
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

    const header: JWTHeader = {alg, typ};
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
        algorithms?: SupportedAlgorithm[]; // Whitelist of allowed algorithms
        issuer?: string;
        subject?: string;
        audience?: string | string[];
        jwtId?: string;
        ignoreExpiration?: boolean;
        clockSkew?: number; // in seconds, default 0
        maxTokenAge?: number; // Maximum age in seconds
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

    const {header, payload, signature} = decoded;

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

// Optional: namespace export
export const JWT = {
    sign,
    verify,
    decode,
    algorithms: SignatureAlgorithm
};
