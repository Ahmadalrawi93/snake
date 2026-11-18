# Tenant isolation invariants

SNAKE uses project ownership as the tenant boundary. An authenticated user
must not be able to read or mutate records belonging to another user's
projects by changing a numeric identifier, candidate fingerprint, or nested
resource identifier.

## Query invariants

- Resolve the parent project through `Project.owner_id == actor.id` before
  reading child records.
- For records that carry both `project_id` and a parent identifier, require
  both to match the resolved parent. Do not trust a child row's project field
  independently of its parent relationship.
- Evaluation metrics and evaluation listings join back to the source analysis
  run and require the evaluation project and run project to agree.
- Human finding-decision reads bind the decision project to the owned run.
- Lifecycle events and evidence artifacts bind their project to the owned
  candidate. Lifecycle state is derived only from events in that project.
- Analysis provenance links must match the analysis run's project and target,
  the worker task receipt, the source observation task ID, and the scan job's
  project.

## Error behavior

Return the same not-found response for missing and non-owned parent resources
where practical. Do not return whether a foreign resource exists. Collection
endpoints may return an empty list only after ownership of the parent resource
has been established.

## Regression coverage

The control-plane tests include deliberately inconsistent legacy evaluation
rows whose project field points at one tenant while their analysis run belongs
to another. Such rows must not appear in metrics or evaluation listings.

These checks are application-level defense in depth. Production deployments
must also restrict direct database access, protect backups, and monitor
administrative access. This document is not a claim that every possible
database-corruption scenario is eliminated.
