# Administrator security boundary

Administrative routes require an authenticated active user whose server-side
account role is exactly `admin`. Public registration always creates the
`user` role; it does not accept a role field. Do not grant administrator
roles through public API payloads. Provision and review administrator access
through a trusted out-of-band operator process.

## Authorization review

Authorization records are created as pending and do not grant scanning
permission. An administrator must explicitly approve a record and supply
normalized hostname scope rules. The pending-to-approved/rejected transition
uses a conditional database update, so concurrent administrators cannot both
complete a review after observing the same pending state. The review decision
and audit event are committed in one transaction.

## Scope snapshot revocation

Only active scope snapshots can be revoked. Revocation uses a conditional
active-state update and records the administrator action in the same
transaction. A repeated or concurrent revocation receives HTTP 409 rather
than silently overwriting the prior state.

## Worker identity administration

Worker public keys and pinned HTTPS endpoint records are provisioned by
administrators. Private signing keys are never accepted by these endpoints.
Key and endpoint registration/revocation operations write audit events.
Worker network dispatch remains disabled; registering an endpoint does not
cause an outbound connection.

## Operational controls

- Use separate, individually attributable administrator accounts.
- Keep administrator credentials out of shared workstations and automation.
- Restrict administrative access at the identity and network layers.
- Review audit events for authorization decisions, scope revocations, and
  worker identity changes.
- Do not treat an administrator's approval as proof that the program's
  written authorization is authentic; the reviewer must verify it independently.
