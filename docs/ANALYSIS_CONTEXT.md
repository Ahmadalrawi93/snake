# Deterministic Analysis Context

The context builder converts already authenticated and persisted worker observations into a bounded, deterministic structure for a future model adapter.

## Guarantees

- No network requests, DNS resolution, URL fetching, or redirects.
- No model provider integration or prompt execution.
- Exact semantic duplicates are removed while distinct evidence/source records remain separate.
- URL and hostname observations are grouped by normalized hostname; other observations remain ungrouped.
- Evidence text is truncated to a configured bound and remains untrusted data.
- The context carries an explicit trust notice: embedded text is data, never instructions.
- The builder does not infer vulnerabilities, severity, exploitability, or confirmation.

## Limits

The default input cap is 5,000 observations. Per-observation evidence is capped at 2,000 characters in the context. A future provider adapter must additionally enforce token budgets, redact secrets, isolate system instructions from evidence, and validate model output with the strict ObservationTriage schema and evidence-reference validator.

No scanning or execution is enabled.


The DeepSeek adapter also derives a bounded application-surface inventory from this redacted context. See [Application Intelligence Profile](APPLICATION_INTELLIGENCE.md). This inventory is descriptive only and never triggers probes.
