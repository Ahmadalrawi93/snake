# Application Intelligence Profile

SNAKE builds a deterministic application-surface inventory from already persisted and redacted observations.

## Included data

- Observed hostnames and their source observation IDs.
- Explicit technology observations.
- Software-identifying response headers (such as `Server` and `X-Powered-By`) as unverified technology clues.
- Observed URL path templates, with numeric and UUID-like segments normalized to `:id`.
- Weak route-name labels for authentication, object access, account, payment, and admin surfaces.

## Guarantees and limitations

- No HTTP requests, DNS lookups, crawling, route guessing, or active tests.
- No inferred framework or backend when it was not observed.
- Query strings are not included in route templates.
- Technology and route labels are clues, not verified facts. A route named `/admin` does not prove administrative access; `/users/:id` does not prove IDOR.
- Every host, route and technology entry retains observation IDs.
- The profile is bounded and generated from the same target-scoped context supplied to the analysis call.
- The model receives the profile as supplementary context; current evidence remains authoritative and independent validation remains mandatory.

The profile is an inventory aid, not a vulnerability scanner or application crawler.

## Feedback scope binding

When historical human feedback is supplied to the DeepSeek adapter, the caller must also pass the expected project ID and target ID for the current analysis. The adapter rejects a profile whose project or target does not match, and rejects feedback supplied without an explicit expected project scope. A null target ID is an explicit legacy/project-wide scope and matches only another null target ID; it is not interchangeable with a target-specific profile. The caller must derive these expected IDs from the authenticated, ownership-checked analysis request, not from model output or client-provided free-form context.
