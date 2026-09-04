import * as ed25519 from '@noble/ed25519';
import { base58btc } from 'multiformats/bases/base58';
import { readFile, mkdir, writeFile } from 'node:fs/promises';

const ISSUER_PRIVATE_KEY_FILE = './private/issuer-private-key.hex';
const ISSUER_PUBLIC_KEY_FILE = './private/issuer-public-key.hex';
const HOLDER_PUBLIC_KEY_FILE = './private/holder-public-key.hex';
const OUTPUT_FILE = './src/test-fixtures/valid.json';

function hexToBytes(hex) {
  return new Uint8Array(Buffer.from(hex.trim(), 'hex'));
}

function publicKeyToDid(publicKeyHex) {
  const publicKey = hexToBytes(publicKeyHex);

  const didBytes = new Uint8Array(2 + publicKey.length);
  didBytes.set([0xed, 0x01], 0);
  didBytes.set(publicKey, 2);

  return `did:key:${base58btc.encode(didBytes)}`;
}

function base64UrlEncode(value) {
  return Buffer.from(value).toString('base64url');
}

async function main() {
  await mkdir('./src/test-fixtures', { recursive: true });

  const issuerPrivateKeyHex = await readFile(
    ISSUER_PRIVATE_KEY_FILE,
    'utf8'
  );

  const issuerPublicKeyHex = await readFile(
    ISSUER_PUBLIC_KEY_FILE,
    'utf8'
  );

  const holderPublicKeyHex = await readFile(
    HOLDER_PUBLIC_KEY_FILE,
    'utf8'
  );

  const issuerDid = publicKeyToDid(issuerPublicKeyHex);
  const holderDid = publicKeyToDid(holderPublicKeyHex);

  const verificationMethod = `${issuerDid}#${issuerDid.replace(
    'did:key:',
    ''
  )}`;

  const validUntil = new Date(
    Date.now() + 30 * 24 * 60 * 60 * 1000
  );

  const credentialBody = {
    "@context": [
      "https://www.w3.org/ns/credentials/v2"
    ],
    "type": [
      "VerifiableCredential",
      "IhifixTrainingCredential"
    ],
    "issuer": {
      "id": issuerDid,
      "name": "Ihifix Training Authority"
    },
    "validFrom": new Date().toISOString(),
    "validUntil": validUntil.toISOString(),
    "audience": "/training-access",
    "credentialSubject": {
      "id": holderDid,
      "course": "Application Security Foundations",
      "cohort": "Cohort 2",
      "status": "active",
      "permittedActions": [
        "read-training-lab"
      ]
    }
  };

  const protectedHeader = {
    alg: "EdDSA",
    typ: "VC-CLASSROOM-JWS",
    kid: verificationMethod
  };

  const encodedHeader = base64UrlEncode(
    JSON.stringify(protectedHeader)
  );

  const encodedPayload = base64UrlEncode(
    JSON.stringify(credentialBody)
  );

  const signingInput = Buffer.from(
    `${encodedHeader}.${encodedPayload}`,
    'utf8'
  );

  const signature = await ed25519.signAsync(
    signingInput,
    hexToBytes(issuerPrivateKeyHex)
  );

  const encodedSignature = Buffer.from(signature).toString(
    'base64url'
  );

  const credential = {
    ...credentialBody,
    proof: {
      type: "Ed25519Signature2020",
      proofPurpose: "assertionMethod",
      verificationMethod,
      jws: `${encodedHeader}.${encodedPayload}.${encodedSignature}`
    }
  };

  await writeFile(
    OUTPUT_FILE,
    JSON.stringify(credential, null, 2) + '\n'
  );

  console.log('Valid fixture created successfully.');
  console.log('Issuer DID:', issuerDid);
  console.log('Holder DID:', holderDid);
  console.log('Output:', OUTPUT_FILE);
}

main().catch((error) => {
  console.error('Failed to create valid fixture:', error);
  process.exit(1);
});
