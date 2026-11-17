# AI Analysis Persistence

SNAKE stores completed AI triage as immutable, evidence-linked analysis history.

## Stored
- Project and initiating user ownership.
- SHA-256 digests of the canonical analysis context and correlation report.
- Provider/model, completion status, validated triage JSON, optional token counts, optional decimal cost string, and provider request ID.
- Fixed disposition `requires_independent_validation`; `execution_enabled` is always false.

## Not stored
- API keys, authorization headers, raw prompts, raw observations, or unredacted evidence.
- A model-generated severity or confirmed-vulnerability status.

The analysis service accepts only an already validated `ObservationTriage`. It does not call DeepSeek or any other provider. Provider invocation remains explicit and separate. Reads are restricted to the owning project. Analysis rows are append-only at the database layer on SQLite and PostgreSQL.

Token and cost metadata are optional because providers may omit usage information. A missing value means unknown, not zero. AI confidence is not independent validation and does not establish impact. Human verification and a separate finding workflow are still required.
