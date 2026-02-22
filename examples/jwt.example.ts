import { generateKeyPairSync } from 'crypto';
import { decode, sign, verify } from '../src';

const secret = 'my-super-secret';

const token = sign(
    { sub: 'user-123', role: 'admin', iat: Math.floor(Date.now() / 1000) },
    secret,
    { alg: 'HS256' }
);

const verified = verify(token, secret);
if (!verified.valid) {
    throw new Error(`Verification failed: ${verified.error.code} (${verified.error.reason})`);
}

console.log('HS256 payload:', verified.payload);
console.log('HS256 header:', verified.header);

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

const rsaToken = sign(
    { sub: 'user-456', scope: 'read:all', iat: Math.floor(Date.now() / 1000) },
    privateKey,
    { kid: 'rsa-key-1' }
);

const rsaVerified = verify(rsaToken, publicKey, { algorithms: ['RS256'] });
if (!rsaVerified.valid) {
    throw new Error(`RSA verification failed: ${rsaVerified.error.code} (${rsaVerified.error.reason})`);
}

console.log('RSA token decoded:', decode(rsaToken));
