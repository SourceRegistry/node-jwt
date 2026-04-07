import {
    type JWT as JSONWebToken,
    decode as decodeSync,
    sign as signSync,
    verify as verifySync,
    JWTPayload,
    JWTHeader,
    SignatureAlgorithm
} from '../index.js';

export {
    type SupportedAlgorithm, SupportedAlgorithms, SignatureAlgorithm, type JWTHeader, type JWTPayload
} from '../index.js';

/**
 * Decode a JWT string into its parts (without verification)
 * @param token
 */
export const decode = (token: string): Promise<JSONWebToken> =>
    Promise.resolve().then(() => decodeSync(token));

/**
 * Sign a JWT
 * @see(synchronous parameters)
 */
export const sign = (...args: Parameters<typeof signSync>): Promise<string> =>
    Promise.resolve().then(() => signSync(...args));

/**
 * Verify and validate a JWT
 * @throws { { reason: string; code: string } } if invalid
 */
export const verify = (...args: Parameters<typeof verifySync>): Promise<{
    header: JWTHeader;
    payload: JWTPayload;
    signature: string
}> =>
    Promise.resolve().then(() => {
        const result = verifySync(...args);
        if ('error' in result) {
            throw result.error;
        }
        const {header, payload, signature} = result;
        return {header, payload, signature};
    });

export type JWT = JSONWebToken;

//namespace export
export const JWT = {
    sign,
    verify,
    decode,
    algorithms: SignatureAlgorithm
};
