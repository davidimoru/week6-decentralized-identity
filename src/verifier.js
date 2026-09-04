import * as ed25519 from '@noble/ed25519';
import { readFile } from 'node:fs/promises';

const POLICY_FILE = './src/policy.json';
const ISSUER_PUBLIC_KEY_FILE = './private/issuer-public-key.hex';

function base64UrlToBytes(value) {
  return new Uint8Array(Buffer.from(value, 'base64url'));
}

function hexToBytes(hex) {
  return new Uint8Array(Buffer.from(hex.trim(), 'hex'));
}

function result(decision, reason_code, checks) {
  return {
    decision,
    reason_code,
    checks
  };
}

function deny(reason_code, checks) {
  console.log(JSON.stringify(result('DENY', reason_code, checks), null, 2));
  process.exitCode = 1;
}

function allow(checks) {
  console.log(
    JSON.stringify(
      result('ALLOW', 'ALL_REQUIRED_CHECKS_PASSED', checks),
      null,
      2
    )
  );
}

function getOption(name, fallback = null) {
  const index = process.argv.indexOf(name);

  if (index === -1) {
    return fallback;
  }

  return process.argv[index + 1] ?? fallback;
}

function getFixturePath() {
  return getOption('--fixture', './src/test-fixtures/valid.json');
}

async function verifySignature(credential, issuerPublicKey) {
  const proof = credential?.proof;

  if (!proof?.jws) {
    return false;
  }

  const parts = proof.jws.split('.');

  if (parts.length !== 3) {
    return false;
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  const { proof: ignoredProof, ...credentialBody } = credential;

  const currentPayload = Buffer.from(
    JSON.stringify(credentialBody),
    'utf8'
  ).toString('base64url');

  // This prevents someone from changing the credential body
  // after the original payload was signed.
  if (currentPayload !== encodedPayload) {
    return false;
  }

  const signingInput = Buffer.from(
    `${encodedHeader}.${encodedPayload}`,
    'utf8'
  );

  const signature = base64UrlToBytes(encodedSignature);

  return await ed25519.verifyAsync(
    signature,
    signingInput,
    issuerPublicKey
  );
}

async function main() {
  if (process.argv.includes('--help')) {
    console.log(`
Usage:

node src/verifier.js --fixture <path> --holder <holder-did> --action <action>

Examples:

node src/verifier.js \\
  --fixture src/test-fixtures/valid.json \\
  --holder did:key:... \\
  --action read-training-lab
`);
    return;
  }

  const checks = {
    signature: 'FAIL',
    issuer: 'FAIL',
    type: 'FAIL',
    required_claims: 'FAIL',
    expiry: 'FAIL',
    status: 'FAIL',
    subject: 'FAIL',
    audience: 'FAIL',
    action: 'FAIL'
  };

  let policy;
  let credential;

  try {
    policy = JSON.parse(await readFile(POLICY_FILE, 'utf8'));
    credential = JSON.parse(
      await readFile(getFixturePath(), 'utf8')
    );
  } catch {
    deny('MALFORMED_INPUT', checks);
    return;
  }

  const presentedHolder = getOption('--holder');
  const requestedAction = getOption(
    '--action',
    'read-training-lab'
  );

  let issuerPublicKey;

  try {
    issuerPublicKey = hexToBytes(
      await readFile(ISSUER_PUBLIC_KEY_FILE, 'utf8')
    );
  } catch {
    deny('MALFORMED_INPUT', checks);
    return;
  }

  /*
   * CHECK 1: ISSUER TRUST
   *
   * A valid signature alone is not enough.
   * The issuer must be explicitly trusted by policy.
   */
  const credentialIssuer =
    typeof credential?.issuer === 'string'
      ? credential.issuer
      : credential?.issuer?.id;

  if (credentialIssuer !== policy.acceptedIssuer) {
    deny('ISSUER_NOT_TRUSTED', checks);
    return;
  }

  checks.issuer = 'PASS';

  /*
   * CHECK 2: SIGNATURE
   */
  if (!(await verifySignature(credential, issuerPublicKey))) {
    deny('SIGNATURE_INVALID', checks);
    return;
  }

  checks.signature = 'PASS';

  /*
   * CHECK 3: CREDENTIAL TYPE
   */
  const credentialTypes = Array.isArray(credential?.type)
    ? credential.type
    : [credential?.type];

  if (!credentialTypes.includes(policy.acceptedType)) {
    deny('CREDENTIAL_TYPE_NOT_ACCEPTED', checks);
    return;
  }

  checks.type = 'PASS';

  /*
   * CHECK 4: REQUIRED CLAIMS
   */
  const subject = credential?.credentialSubject;

  const missingClaim = policy.requiredClaims.find(
    (claim) => subject?.[claim] === undefined
  );

  if (missingClaim) {
    deny('REQUIRED_CLAIM_MISSING', checks);
    return;
  }

  checks.required_claims = 'PASS';

  /*
   * CHECK 5: EXPIRY
   */
  if (credential?.validUntil) {
    const expiryTime = Date.parse(credential.validUntil);

    if (Number.isNaN(expiryTime)) {
      deny('MALFORMED_INPUT', checks);
      return;
    }

    if (expiryTime <= Date.now()) {
      deny('CREDENTIAL_EXPIRED', checks);
      return;
    }
  }

  checks.expiry = 'PASS';

  /*
   * CHECK 6: STATUS
   */
  if (subject.status !== policy.requiredStatus) {
    deny('CREDENTIAL_NOT_ACTIVE', checks);
    return;
  }

  checks.status = 'PASS';

  /*
   * CHECK 7: HOLDER / SUBJECT
   */
  if (presentedHolder && subject.id !== presentedHolder) {
    deny('SUBJECT_MISMATCH', checks);
    return;
  }

  checks.subject = 'PASS';

  /*
   * CHECK 8: AUDIENCE
   */
  if (
    policy.requireAudience &&
    credential.audience !== policy.endpoint
  ) {
    deny('AUDIENCE_MISMATCH', checks);
    return;
  }

  checks.audience = 'PASS';

  /*
   * CHECK 9: ACTION AUTHORIZATION
   */
  const permittedActions = Array.isArray(subject.permittedActions)
    ? subject.permittedActions
    : [];

  const actionAllowed =
    policy.allowedActions.includes(requestedAction) &&
    permittedActions.includes(requestedAction);

  if (!actionAllowed) {
    deny('ACTION_NOT_ALLOWED', checks);
    return;
  }

  checks.action = 'PASS';

  /*
   * ALL CHECKS PASSED
   */
  allow(checks);
}

main().catch(() => {
  const checks = {
    signature: 'FAIL',
    issuer: 'FAIL',
    type: 'FAIL',
    required_claims: 'FAIL',
    expiry: 'FAIL',
    status: 'FAIL',
    subject: 'FAIL',
    audience: 'FAIL',
    action: 'FAIL'
  };

  deny('MALFORMED_INPUT', checks);
});
