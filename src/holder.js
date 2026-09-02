import { readFile, writeFile, mkdir, chmod } from 'node:fs/promises';
import * as ed from '@noble/ed25519';
import { base58btc } from 'multiformats/bases/base58';

const PRIVATE_KEY_PATH = './private/holder-private-key.hex';
const PUBLIC_KEY_PATH = './private/holder-public-key.hex';

async function fileExists(path) {
  try {
    await readFile(path);
    return true;
  } catch {
    return false;
  }
}

function bytesToHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

function hexToBytes(hex) {
  return Uint8Array.from(Buffer.from(hex.trim(), 'hex'));
}

async function createKeyPair() {
  await mkdir('./private', { recursive: true });

  const privateKey = ed.utils.randomSecretKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);

  await writeFile(
    PRIVATE_KEY_PATH,
    bytesToHex(privateKey),
    { encoding: 'utf8', mode: 0o600 }
  );

  await writeFile(
    PUBLIC_KEY_PATH,
    bytesToHex(publicKey),
    { encoding: 'utf8', mode: 0o644 }
  );

  await chmod(PRIVATE_KEY_PATH, 0o600);

  return { privateKey, publicKey, created: true };
}

async function loadKeyPair() {
  const privateKeyHex = await readFile(PRIVATE_KEY_PATH, 'utf8');
  const publicKeyHex = await readFile(PUBLIC_KEY_PATH, 'utf8');

  return {
    privateKey: hexToBytes(privateKeyHex),
    publicKey: hexToBytes(publicKeyHex),
    created: false
  };
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
  const keysExist =
    await fileExists(PRIVATE_KEY_PATH) &&
    await fileExists(PUBLIC_KEY_PATH);

  const { privateKey, publicKey, created } = keysExist
    ? await loadKeyPair()
    : await createKeyPair();

  if (privateKey.length !== 32) {
    throw new Error('Holder private key must be 32 bytes.');
  }

  if (publicKey.length !== 32) {
    throw new Error('Holder public key must be 32 bytes.');
  }

  const { did, fingerprint } = createDid(publicKey);

  console.log(
    created
      ? 'Holder key pair created and saved.'
      : 'Existing holder key pair loaded.'
  );

  console.log('Holder DID:', did);
  console.log('Verification method:', `${did}#${fingerprint}`);
  console.log('Private key: [redacted]');
  console.log('Public key length:', publicKey.length, 'bytes');
}

main().catch((error) => {
  console.error('Holder setup failed:', error.message);
  process.exit(1);
});
