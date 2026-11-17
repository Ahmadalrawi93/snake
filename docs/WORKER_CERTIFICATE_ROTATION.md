# Worker certificate rotation runbook

## Current limitation

SNAKE stores one active server-certificate SHA-256 pin per worker endpoint and
the listener accepts one exact backend client-certificate pin. There is no
dual-pin/overlap mechanism. Rotation is therefore a coordinated maintenance
operation, not zero-downtime rotation.

## Controlled rotation

1. Stop all delivery activity. The current repository does not enable a delivery
   route or dispatcher; if one is introduced later, disable it and verify it is
   stopped before proceeding.
2. Generate the replacement certificates and private keys in the approved
   secret-management environment. Validate names, EKUs, validity windows,
   chain, and key/certificate matching. Never place private keys in Git.
3. Prepare the worker with the new backend-client CA trust and new exact backend
   client-certificate SHA-256 pin. Prepare the backend endpoint record with the
   new worker server-certificate fingerprint and unchanged registered TLS name.
4. Deploy the worker server certificate/key and backend client certificate/key
   as one coordinated change. Update the endpoint fingerprint through the
   administrator-controlled registry operation.
5. Run a real mTLS handshake, then a signed validation task and signed
   acknowledgement round trip. Verify the expected worker ID/key ID, TLS
   hostname, CA chain, both exact certificate pins, and durable replay behavior.
6. Restore connectivity only after all checks pass. Retain old material offline
   only for the approved rollback window, then revoke and securely retire it.

## Failure and rollback

If any validation fails, keep delivery disabled. Restore the previous endpoint
fingerprint, trust configuration, and certificate/key set together; do not mix
old and new halves of the mTLS pair. Re-run the handshake and signed round trip
before considering rollback complete.

## Change record

Record the worker ID, certificate subject/SAN, serial number, SHA-256
fingerprint, issuer, not-before/not-after timestamps, change approver, deployment
window, validation result, and retirement/revocation date. Record metadata only;
never record private key bytes or secret values.

## Future engineering requirement

Before production availability or zero-downtime rotation, implement versioned
certificate identities with a bounded set of simultaneously trusted pins,
atomic activation/deactivation, audit events, expiry monitoring, and tests for
old/new overlap, rollback, revoked certificates, and concurrent rotations.
