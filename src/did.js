import { readFile } from 'node:fs/promises';
import { base58btc } from 'multiformats/bases/base58';

const PUBLIC_KEY_PATH = './private/issuer-public-key.hex';

function hexToBytes(hex) {
  return Uint8Array.from(Buffer.from(hex.trim(), 'hex'));
}

async function main() {
  const publicKeyHex = await readFile(PUBLIC_KEY_PATH, 'utf8');
  const publicKey = hexToBytes(publicKeyHex);

  if (publicKey.length !== 32) {
    throw new Error('Issuer public key must be 32 bytes.');
  }

  // Multicodec prefix for Ed25519 public keys.
  const multicodecPrefix = Uint8Array.from([0xed, 0x01]);

  const fingerprintBytes = new Uint8Array(
    multicodecPrefix.length + publicKey.length
  );

  fingerprintBytes.set(multicodecPrefix);
  fingerprintBytes.set(publicKey, multicodecPrefix.length);

  const fingerprint = base58btc.encode(fingerprintBytes);
  const did = `did:key:${fingerprint}`;
  const verificationMethod = `${did}#${fingerprint}`;

  const didDocument = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    verificationMethod: [
      {
        id: verificationMethod,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase: fingerprint
      }
    ],
    authentication: [verificationMethod],
    assertionMethod: [verificationMethod]
  };

  console.log('Issuer DID created successfully.');
  console.log('DID:', did);
  console.log('Verification method:', verificationMethod);
  console.log('Key type: Ed25519');
  console.log('DID document:');
  console.log(JSON.stringify(didDocument, null, 2));
}

main().catch((error) => {
  console.error('DID creation failed:', error.message);
  process.exit(1);
});
