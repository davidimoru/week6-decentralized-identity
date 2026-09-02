# DID Inspection Evidence

## Issuer identity

This lab uses a fictional classroom issuer identity.

- DID method: `did:key`
- Key type: Ed25519
- DID:

`did:key:z6MkoJ7jNnZiDVLX76oSU8PoKWkzCdbNLNbr3iTb2qaqp7PE`

- Verification method:

`did:key:z6MkoJ7jNnZiDVLX76oSU8PoKWkzCdbNLNbr3iTb2qaqp7PE#z6MkoJ7jNnZiDVLX76oSU8PoKWkzCdbNLNbr3iTb2qaqp7PE`

## DID document

The local DID document demonstrates:

- `id`
- `verificationMethod`
- `authentication`
- `assertionMethod`

The verification method identifies the public Ed25519 verification key associated with the issuer DID.

## Security notes

The issuer private key is stored locally under the ignored `private/` directory and is never included in this evidence.

This classroom demonstration does not establish:

- Real-world issuer reputation
- Governance
- Credential revocation
- Key recovery
- Production identity assurance
- Authorization for a real system

A cryptographically derived DID and valid signature demonstrate cryptographic identity and integrity, but they do not automatically establish trust or authorization.
