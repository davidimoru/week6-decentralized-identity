# AI Journal — Decentralized Identity

## Prompt Used

I am teaching a local, fictional DID and Verifiable Credential lab. Explain the roles of issuer, holder, verifier, DID document, credential, and presentation. Suggest a minimal JSON structure for a classroom credential and list three security limitations of a local demo. Do not invent production guarantees or cryptographic algorithms.

## AI-Assisted Understanding

### Issuer

The issuer creates a credential containing claims about a subject and signs the credential. In this lab, the fictional training authority acts as the issuer.

### Holder

The holder is the entity that receives and stores the credential. The holder can later present the credential to a verifier.

### Verifier

The verifier checks whether the credential and its cryptographic proof are valid. In this lab, the verifier checks the issuer's digital signature and detects whether the credential payload has been changed.

### DID

A Decentralized Identifier (DID) provides an identifier for an entity. This lab uses fictional `did:key` identifiers derived from Ed25519 public keys.

### DID Document

A DID document describes information associated with a DID, including verification methods and relationships such as authentication and assertionMethod.

### Credential

A credential contains claims about a subject. In this classroom lab, the credential contains fictional course-completion information.

### Presentation

A presentation is how a holder can share credential information with a verifier. A production presentation system can include additional privacy and proof mechanisms, but this local lab does not implement a full production presentation protocol.

## Minimal Classroom Credential Structure

A minimal classroom credential can contain:

- `@context`
- `type`
- `issuer`
- `validFrom`
- `credentialSubject`
- `proof`

The `credentialSubject` contains the claims being made about the holder, while the `proof` provides cryptographic evidence that the credential was signed.

## Security Limitations

1. Cryptographic verification does not automatically establish that an issuer is trustworthy. A local classroom issuer does not have real-world reputation or governance.

2. Signature verification does not automatically establish revocation or current credential status. A production system needs separate mechanisms for status and revocation.

3. A valid credential does not automatically mean that the holder is authorized to perform a particular action. Application-level authorization decisions must still be made by the relying system.

## Claims Checked

### Claim 1

A DID document can contain verification methods and relationships such as authentication and assertionMethod.

**Assessment:** Correct.

### Claim 2

Changing a signed credential claim should cause cryptographic verification to fail.

**Assessment:** Correct. This was demonstrated by changing the credential status from `completed` to `administrator`. The modified credential failed verification.

### Claim 3

Cryptographic verification automatically proves that the issuer is trustworthy and that the holder is authorized.

**Assessment:** Misleading.

Cryptographic verification primarily demonstrates that the signed data has not been modified and that the signature corresponds to the verification key. Trust in the issuer, credential status, governance, and application authorization are separate concerns.

## Refinement

The key distinction from this exercise is:

**Cryptographic integrity is not the same as trust or authorization.**

A verifier should distinguish between:

- signature validity
- issuer trust
- credential status or revocation
- privacy requirements
- application-specific authorization

The Week 6 lab demonstrates cryptographic integrity and verification, not a complete production decentralized identity system.
