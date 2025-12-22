import type {KeyObject} from 'crypto';

import {
    type JWK as JWKType,
    type JWKS as JSONWebKeySet,
    exportJWK as exportJWKSYNC,
    importJWK as importJWKSYNC,
    toPublicJWK as toPublicJWKSYNC,
    getJWKThumbprint as getJWKThumbprintSYNC,
    JWKSToKeyObject as JWKSToKeyObjectSYNC,
    normalizeJWKS as normalizeJWKSSYNC,
    computeX5T as computeX5TSYNC
} from './';

/**
 * Export a KeyObject to JWK
 * @param key
 */
export const exportJWK = (key: KeyObject): Promise<JWKType> =>
    Promise.resolve().then(() => exportJWKSYNC(key));

/**
 * Import a JWK to KeyObject
 * @param jwk
 */
export const importJWK = (jwk: JWKType): Promise<KeyObject> =>
    Promise.resolve().then(() => importJWKSYNC(jwk));

/**
 * Export public-only JWK
 * @param key
 */
export const toPublicJWK = (key: KeyObject): Promise<JWKType> =>
    Promise.resolve().then(() => toPublicJWKSYNC(key));

/**
 * RFC 7638 JWK thumbprint
 * @param jwk
 * @param hashAlg
 */
export const getJWKThumbprint = (
    jwk: JWKType,
    hashAlg: 'sha256' = 'sha256'
): Promise<string> =>
    Promise.resolve().then(() => getJWKThumbprintSYNC(jwk, hashAlg));

/**
 * Resolve a KeyObject from a JWKS (kid-based)
 * @param jwks
 * @param kid
 * @constructor
 */
export const JWKSToKeyObject = (
    jwks: JSONWebKeySet,
    kid?: string
): Promise<KeyObject> =>
    Promise.resolve().then(() => JWKSToKeyObjectSYNC(jwks, kid));

/**
 * Normalize JWKS (auto-generate missing kid values)
 * @param jwks
 */
export const normalizeJWKS = (
    jwks: JSONWebKeySet
): Promise<JSONWebKeySet> =>
    Promise.resolve().then(() => normalizeJWKSSYNC(jwks));

/**
 * Compute x5t (SHA-1) from first cert in x5c if not set
 * @param jwk
 */
export const computeX5T = (jwk: JWKType) => Promise.resolve().then(() => computeX5TSYNC(jwk))

//namespaced exports
export const JWK = {
    export: exportJWK,
    import: importJWK,
    toPublic: toPublicJWK,
    thumbprint: getJWKThumbprint,
    computeX5T: computeX5T,
};

//namespaced exports
export const JWKS = {
    toKeyObject: JWKSToKeyObject,
    normalize: normalizeJWKS,
};
