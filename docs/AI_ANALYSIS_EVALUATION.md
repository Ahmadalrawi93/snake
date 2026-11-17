# Human Evaluation of AI Hypotheses

SNAKE records a separate, append-only human evaluation for each AI analysis run.

## Outcomes
- `confirmed`: a human independently reproduced/verified the hypothesis; an evidence SHA-256 digest is mandatory.
- `false_positive`: human review rejected the hypothesis; an evidence digest is mandatory to bind the review artifact.
- `inconclusive`: available evidence cannot resolve the hypothesis.
- `duplicate`: the hypothesis repeats an existing finding or previously reviewed hypothesis.

Only the authenticated project owner can submit evaluations or read project metrics. AI triage cannot submit its own evaluation. Evaluations do not mutate the original AI analysis run and cannot enable scanner execution.

## Metrics
- Resolved precision = confirmed / (confirmed + false_positive). Inconclusive and duplicate cases are excluded.
- Resolution coverage = (confirmed + false_positive) / all reviewed evaluations.
- Counts for each outcome are reported separately. A low coverage value means the apparent precision is based on a small resolved subset; metrics must not be presented without both values.

These are project-level operational metrics, not proof of general model quality. They are not stratified by model/version or category yet. Evidence digests bind the review artifact but do not prove its contents or authenticity.
