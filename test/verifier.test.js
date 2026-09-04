import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const validFixture = JSON.parse(
  readFileSync('src/test-fixtures/valid.json', 'utf8')
);

const VALID_HOLDER_DID = validFixture.credentialSubject.id;

function runVerifier(
  fixture,
  holder = VALID_HOLDER_DID,
  action = 'read-training-lab'
) {
  try {
    const output = execFileSync(
      'node',
      [
        'src/verifier.js',
        '--fixture',
        fixture,
        '--holder',
        holder,
        '--action',
        action
      ],
      { encoding: 'utf8' }
    );

    return JSON.parse(output);
  } catch (err) {
    return JSON.parse(err.stdout.toString());
  }
}

test('Valid credential should yield ALLOW', () => {
  const result = runVerifier('src/test-fixtures/valid.json');

  assert.equal(result.decision, 'ALLOW');
  assert.equal(result.reason_code, 'ALL_REQUIRED_CHECKS_PASSED');
});

test('Tampered credential should yield SIGNATURE_INVALID', () => {
  const result = runVerifier('src/test-fixtures/tampered.json');

  assert.equal(result.decision, 'DENY');
  assert.equal(result.reason_code, 'SIGNATURE_INVALID');
});

test('Untrusted issuer should yield ISSUER_NOT_TRUSTED', () => {
  const result = runVerifier('src/test-fixtures/untrusted-issuer.json');

  assert.equal(result.decision, 'DENY');
  assert.equal(result.reason_code, 'ISSUER_NOT_TRUSTED');
});

test('Expired credential should yield CREDENTIAL_EXPIRED', () => {
  const result = runVerifier('src/test-fixtures/expired.json');

  assert.equal(result.decision, 'DENY');
  assert.equal(result.reason_code, 'CREDENTIAL_EXPIRED');
});

test('Missing claim should yield REQUIRED_CLAIM_MISSING', () => {
  const result = runVerifier('src/test-fixtures/missing-claim.json');

  assert.equal(result.decision, 'DENY');
  assert.equal(result.reason_code, 'REQUIRED_CLAIM_MISSING');
});

test('Unauthorized action should yield ACTION_NOT_ALLOWED', () => {
  const result = runVerifier(
    'src/test-fixtures/valid.json',
    VALID_HOLDER_DID,
    'delete-root-database'
  );

  assert.equal(result.decision, 'DENY');
  assert.equal(result.reason_code, 'ACTION_NOT_ALLOWED');
});
