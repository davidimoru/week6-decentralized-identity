import { readFile, writeFile, mkdir, chmod } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import * as ed from '@noble/ed25519';

const PRIVATE_KEY_PATH = './private/issuer-private-key.hex';
const PUBLIC_KEY_PATH = './private/issuer-public-key.hex';

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

  const privateKey = hexToBytes(privateKeyHex);
  const publicKey = hexToBytes(publicKeyHex);

  return { privateKey, publicKey, created: false };
}

async function main() {
  const keysExist =
    await fileExists(PRIVATE_KEY_PATH) &&
    await fileExists(PUBLIC_KEY_PATH);

  const { privateKey, publicKey, created } = keysExist
    ? await loadKeyPair()
    : await createKeyPair();

  if (privateKey.length !== 32) {
    throw new Error('Issuer private key must be 32 bytes.');
  }

  if (publicKey.length !== 32) {
    throw new Error('Issuer public key must be 32 bytes.');
  }

  console.log(
    created
      ? 'Issuer key pair created and saved.'
      : 'Existing issuer key pair loaded.'
  );

  console.log('Private key: [redacted]');
  console.log('Public key saved to:', PUBLIC_KEY_PATH);
  console.log('Public key length:', publicKey.length, 'bytes');
}

main().catch((error) => {
  console.error('Key setup failed:', error.message);
  process.exit(1);
});
