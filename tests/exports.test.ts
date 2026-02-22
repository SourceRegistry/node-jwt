import { describe, expect, it } from 'vitest';

import * as syncApi from '../src/index';
import * as asyncApi from '../src/promises';

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
    });
});
