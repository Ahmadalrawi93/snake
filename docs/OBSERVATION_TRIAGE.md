# Observation Triage Boundary

The AI triage contract is intentionally separate from worker evidence ingestion.

- Input evidence remains immutable and classified as `unconfirmed_observation`.
- Model output is parsed with a strict Pydantic schema; unknown fields are rejected.
- Each hypothesis must cite one or more observation IDs from the exact evidence context supplied to the model.
- The output can express only a bounded hypothesis category, rationale, missing evidence, validation questions, and confidence.
- Its only allowed disposition is `requires_independent_validation`.
- It cannot carry severity, exploit code, commands, scripts, or a confirmed-finding status.

`validate_triage_references` checks provenance references only. It does not prove that the hypothesis is true. A high confidence label is still a model opinion, not a security validation result.

## Next boundary

A future validator must independently reproduce the suspected behavior inside the approved scope, preserve request/response evidence, and apply a separate human approval gate before a vulnerability finding can be created. Model-generated validation questions are suggestions, never executable instructions.

No LLM provider call is wired by this module. No scan or network activity is enabled.
