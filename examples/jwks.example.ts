import { generateKeyPairSync } from 'crypto';
import { JWK, JWKS } from '../src';

async function main() {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

    const publicJwk = JWK.toPublic(publicKey);
    publicJwk.kid = 'rsa-main-key';
    publicJwk.use = 'sig';


    const localJwks = JWKS.normalize({ keys: [publicJwk] });
    const localKey = JWKS.toKeyObject(localJwks, 'rsa-main-key');
    console.log('Local JWKS key type:', localKey.asymmetricKeyType);

    const fetchMock = async () => ({
        ok: true,
        status: 200,
        statusText: 'OK',
        async json() {
            return localJwks;
        }
    }) as unknown as Response;

    const jwks = await JWKS.fromWeb('https://issuer.example', {
        fetch: fetchMock as unknown as typeof fetch,
        ttl: 60_000,
        timeoutMs: 2_000
    });


    const resolvedKey = await jwks.key('rsa-main-key');
    const allKeys = await jwks.list();
    const matching = await jwks.find({ kid: 'rsa-main-key', kty: 'RSA' });
    const first = await jwks.findFirst({ use: 'sig' });

    console.log('Resolved key type:', resolvedKey?.kty ?? '<none>');
    console.log('All keys:', allKeys.length);
    console.log('Matched keys:', matching.length);
    console.log('First matching key kid:', first?.kid ?? '<none>');
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
