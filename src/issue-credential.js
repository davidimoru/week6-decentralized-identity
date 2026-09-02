import { readFile, writeFile } from 'node:fs/promises';
import * as ed from '@noble/ed25519';
import { base64url } from 'multiformats/bases/base64';
import { base58btc } from 'multiformats/bases/base58';

const ISSUER_PRIVATE_KEY_PATH = './private/issuer-private-key.hex';
const ISSUER_PUBLIC_KEY_PATH = './private/issuer-public-key.hex';
const HOLDER_PUBLIC_KEY_PATH = './private/holder-public-key.hex';
const OUTPUT_PATH = './evidence/credential.json';

function hexToBytes(hex) {
  return Uint8Array.from(Buffer.from(hex.trim(), 'hex'));
}

function encodeJson(value) {
  return new TextEncoder().encode(JSON.stringify(value));
}

function encodeBase64Url(bytes) {
  return base64url.baseEncode(bytes);
}

function createDid(publicKey) {
  const multicodecPrefix = Uint8Array.from([0xed, 0x01]);

  const fingerprintBytes = new Uint8Array(
    multicodecPrefix.length + publicKey.length
  );

  fingerprintBytes.set(multicodecPrefix);
  fingerprintBytes.set(publicKey, multicodecPrefix.length);

  const fingerprint = base58btc.encode(fingerprintBytes);

  return {
    did: `did:key:${fingerprint}`,
    fingerprint
  };
}

async function main() {
  const issuerPrivateKey = hexToBytes(
    await readFile(ISSUER_PRIVATE_KEY_PATH, 'utf8')
  );

  const issuerPublicKey = hexToBytes(
    await readFile(ISSUER_PUBLIC_KEY_PATH, 'utf8')
  );

  const holderPublicKey = hexToBytes(
    await readFile(HOLDER_PUBLIC_KEY_PATH, 'utf8')
  );

  if (issuerPrivateKey.length !== 32) {
    throw new Error('Issuer private key must be 32 bytes.');
  }

  if (issuerPublicKey.length !== 32) {
    throw new Error('Issuer public key must be 32 bytes.');
  }

  if (holderPublicKey.length !== 32) {
    throw new Error('Holder public key must be 32 bytes.');
  }

  const issuer = createDid(issuerPublicKey);
  const holder = createDid(holderPublicKey);

  const verificationMethod =
    `${issuer.did}#${issuer.fingerprint}`;

  const credentialBody = {
    '@context': [
      'https://www.w3.org/ns/credentials/v2'
    ],
    type: ['VerifiableCredential'],
    issuer: {
      id: issuer.did,
      name: 'Ihifix Training Authority'
    },
    validFrom: new Date().toISOString(),
    credentialSubject: {
      id: holder.did,
      course: 'Application Security Foundations',
      status: 'completed',
      cohort: 'Cohort 2'
    }
  };

  const protectedHeader = {
    alg: 'EdDSA',
    typ: 'VC-CLASSROOM-JWS',
    kid: verificationMethod
  };

  const encodedHeader = encodeBase64Url(
    encodeJson(protectedHeader)
  );

  const encodedPayload = encodeBase64Url(
    encodeJson(credentialBody)
  );

  const signingInput = new TextEncoder().encode(
    `${encodedHeader}.${encodedPayload}`
  );

  const signature = await ed.signAsync(
    signingInput,
    issuerPrivateKey
  );

  const jws =
    `${encodedHeader}.${encodedPayload}.${encodeBase64Url(signature)}`;

  const credential = {
    ...credentialBody,
    proof: {
      type: 'Ed25519Signature2020',
      proofPurpose: 'assertionMethod',
      verificationMethod,
      jws
    }
  };

  await writeFile(
    OUTPUT_PATH,
    JSON.stringify(credential, null, 2),
    'utf8'
  );

  console.log('Credential issued successfully.');
  console.log('Issuer DID:', issuer.did);
  console.log('Holder DID:', holder.did);
  console.log('Credential saved to:', OUTPUT_PATH);
  console.log('Private key: [redacted]');
}

main().catch((error) => {
  console.error('Credential issuance failed:', error.message);
  process.exit(1);
});
