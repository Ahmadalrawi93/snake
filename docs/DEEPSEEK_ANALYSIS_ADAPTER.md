# DeepSeek Analysis Adapter

The adapter is an explicitly invoked, synchronous provider boundary. It sends the bounded analysis context and deterministic evidence correlations to the fixed HTTPS DeepSeek API endpoint.

## Controls
- No provider call occurs during app startup, scan creation, worker dispatch, or context construction.
- Fixed HTTPS API URL; redirects disabled; no caller-supplied URL or proxy configuration.
- API key is supplied at invocation and is never persisted or logged by this module.
- Request and response byte limits, bounded timeout, no automatic retries.
- No tools, function calling, shell, browser, scanner, or action execution.
- System message treats all supplied observations as untrusted data, not instructions.
- JSON-only response parsed against the strict ObservationTriage schema.
- Every cited observation ID is checked against the exact context sent to the model.
- Model output remains a hypothesis requiring independent validation; it cannot create a confirmed finding.

## Current limitations
- This adapter does not yet persist prompts, outputs, token usage, cost, or provider request IDs.
- The API key and model are passed by the caller; secret-manager integration and an authenticated API route are not implemented.
- Prompt injection cannot be solved by wording alone. The security boundary is that the model receives no tools or execution capability and its output is schema/provenance checked.
- Do not send sensitive customer data or secrets in evidence. Redaction and retention policy must be implemented before production use.
- The configured model identifier must be verified against the provider account; the adapter does not assume a specific model alias.
