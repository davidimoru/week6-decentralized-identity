import { readFile } from 'node:fs/promises';
import * as ed from '@noble/ed25519';
import { base64url } from 'multiformats/bases/base64';

const ISSUER_PUBLIC_KEY_PATH = './private/issuer-public-key.hex';

function hexToBytes(hex) {
  return Uint8Array.from(Buffer.from(hex.trim(), 'hex'));
}

function encodeJson(value) {
  return new TextEncoder().encode(JSON.stringify(value));
}

function fail(message) {
  console.log('Verification: FAIL');
  console.log('Reason: SIGNATURE_INVALID');
  console.log(`Details: ${message}`);
  process.exit(1);
}

async function main() {
  const credentialPath = process.argv[2];

  if (!credentialPath) {
    console.error(
      'Usage: node src/verify-credential.js <credential.json>'
    );
    process.exit(1);
  }

  const issuerPublicKey = hexToBytes(
    await readFile(ISSUER_PUBLIC_KEY_PATH, 'utf8')
  );

  const credential = JSON.parse(
    await readFile(credentialPath, 'utf8')
  );

  if (issuerPublicKey.length !== 32) {
    throw new Error('Issuer public key must be 32 bytes.');
  }

  if (!credential.proof?.jws) {
    throw new Error('Credential proof JWS is missing.');
  }

  const parts = credential.proof.jws.split('.');

  if (parts.length !== 3) {
    throw new Error('Credential JWS must contain three parts.');
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  const { proof, ...credentialBody } = credential;

  const currentEncodedPayload = base64url.baseEncode(
    encodeJson(credentialBody)
  );

  if (currentEncodedPayload !== encodedPayload) {
    fail('Credential payload changed after signing.');
  }

  const signingInput = new TextEncoder().encode(
    `${encodedHeader}.${encodedPayload}`
  );

  const signature = base64url.baseDecode(encodedSignature);

  const valid = await ed.verifyAsync(
    signature,
    signingInput,
    issuerPublicKey
  );

  if (valid) {
    console.log('Verification: PASS');
    console.log('Credential signature is valid.');
  } else {
    fail('Credential signature is invalid.');
  }
}

main().catch((error) => {
  console.error('Verification failed:', error.message);
  process.exit(1);
});
