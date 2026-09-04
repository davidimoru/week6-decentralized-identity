# Verifier Test Matrix

| Test | Fixture / Input | Expected | Actual | Result |
|---|---|---|---|---|
| Valid credential | `valid.json` + correct holder + `read-training-lab` | ALLOW / `ALL_REQUIRED_CHECKS_PASSED` | ALLOW / `ALL_REQUIRED_CHECKS_PASSED` | PASS |
| Untrusted issuer | `untrusted-issuer.json` | DENY / `ISSUER_NOT_TRUSTED` | DENY / `ISSUER_NOT_TRUSTED` | PASS |
| Expired credential | `expired.json` | DENY / `CREDENTIAL_EXPIRED` | DENY / `CREDENTIAL_EXPIRED` | PASS |
| Missing claim | `missing-claim.json` | DENY / `REQUIRED_CLAIM_MISSING` | DENY / `REQUIRED_CLAIM_MISSING` | PASS |
| Unauthorized action | `valid.json` + `delete-root-database` | DENY / `ACTION_NOT_ALLOWED` | DENY / `ACTION_NOT_ALLOWED` | PASS |
