# AI Journal — Wednesday

## Prompt Used

> Review the following local fictional verifier design against the rule “a valid signature proves integrity, not trust, status, or permission.” Identify missing security checks, ordering problems, and fail-open risks. Give concrete suggestions that can be tested in a local classroom lab. Do not assume production guarantees.

## Useful AI Suggestion Tested

The useful suggestion was to treat issuer trust, signature verification, credential validity/status, subject binding, audience, and action authorization as separate security checks.

The verifier should check the issuer against an explicit trusted-issuer policy and fail closed whenever a required check fails.

I tested this using the trusted valid fixture, an untrusted issuer fixture, an expired fixture, a missing-claim fixture, a subject-mismatch fixture, a tampered fixture, and an unauthorized action.

The verifier returned distinct DENY reason codes for the failing checks.

## Vague or Unsuitable Suggestion

A vague or unsafe suggestion would be:

> “If the signature is valid, allow the request.”

I rejected this because it conflicts with the lab's golden rule. A valid signature establishes the integrity of the signed content, but it does not by itself establish that the issuer is trusted, the credential is current, the subject is the expected holder, the credential is intended for the endpoint, or the requested action is authorized.

## Security Lesson Learned

Integrity, issuer trust, credential status, subject binding, audience, and authorization are separate security decisions.

A secure verifier should fail closed and return a safe reason code when any required check fails or cannot be established.
