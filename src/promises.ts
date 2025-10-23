import type { KeyLike } from 'crypto';
import {
    type JWT as JSONWebToken,
    decode as decodeSync,
    sign as signSync,
    verify as verifySync,
    JWTPayload,
    type SupportedAlgorithm,
    JWTHeader,
    SignatureAlgorithm
} from './index.js';

export { type SupportedAlgorithm, SupportedAlgorithms, SignatureAlgorithm, type JWTHeader, type JWTPayload } from './index.js';

/**
 * Decode a JWT string into its parts (without verification)
 */
export const decode = (token: string): Promise<JSONWebToken> =>
    Promise.resolve().then(() => decodeSync(token));

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
): Promise<string> =>
    Promise.resolve().then(() => signSync(payload, secret, options));

/**
 * Verify and validate a JWT
 *
 * @throws { { reason: string; code: string } } if invalid
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
): Promise<{ header: JWTHeader; payload: JWTPayload; signature: string }> =>
    Promise.resolve().then(() => {
        const result = verifySync(token, secret, options);
        if (!result.valid) {
            throw result.error;
        }
        const { header, payload, signature } = result;
        return { header, payload, signature };
    });

export type JWT = JSONWebToken;

export const JWT = {
    sign,
    verify,
    decode,
    algorithms: SignatureAlgorithm
};
