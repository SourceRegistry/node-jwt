import { describe, expect, it } from 'vitest';

import * as syncApi from '../src/index';
import * as asyncApi from '../src/promises';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const testDir = dirname(fileURLToPath(import.meta.url));
const distIndexEsm = resolve(testDir, '../dist/index.js');
const distIndexCjs = resolve(testDir, '../dist/index.cjs');
const distPromisesCjs = resolve(testDir, '../dist/promises.cjs');
const hasBuiltDist = existsSync(distIndexEsm) && existsSync(distIndexCjs) && existsSync(distPromisesCjs);

describe('Package exports', () => {
    it('exposes sync API from src/index', () => {
        expect(typeof syncApi.sign).toBe('function');
        expect(typeof syncApi.verify).toBe('function');
        expect(typeof syncApi.decode).toBe('function');
        expect(typeof syncApi.JWK.export).toBe('function');
        expect(typeof syncApi.JWKS.fromWeb).toBe('function');
    });

    it('exposes promises API from src/promises', () => {
        expect(typeof asyncApi.sign).toBe('function');
        expect(typeof asyncApi.verify).toBe('function');
        expect(typeof asyncApi.decode).toBe('function');
        expect(typeof asyncApi.JWK.export).toBe('function');
        expect(typeof asyncApi.JWKS.normalize).toBe('function');
        expect(typeof asyncApi.JWKS.fromWeb).toBe('function');
    });

    it.skipIf(!hasBuiltDist)('exposes sync API from the built ESM entrypoint', async () => {
        const pkg = await import(pathToFileURL(distIndexEsm).href);
        expect(typeof pkg.sign).toBe('function');
        expect(typeof pkg.verify).toBe('function');
        expect(typeof pkg.decode).toBe('function');
    });

    it.skipIf(!hasBuiltDist)('exposes sync and promises APIs from the built CommonJS entrypoints', () => {
        const require = createRequire(import.meta.url);
        const pkg = require(distIndexCjs);
        const promisesPkg = require(distPromisesCjs);

        expect(typeof pkg.sign).toBe('function');
        expect(typeof pkg.verify).toBe('function');
        expect(typeof promisesPkg.sign).toBe('function');
        expect(typeof promisesPkg.verify).toBe('function');
    });
});
