# Evidence Correlation

This deterministic layer links passive observations into explainable investigation leads.

- Same-host grouping uses the normalized host already present in the analysis context.
- URL route families normalize numeric and UUID-like path segments to `:id`.
- Authentication-related and object/account-related route names produce investigative leads only.
- Every link retains source observation IDs.
- Unlinked evidence remains explicitly listed.
- Link count is bounded.

It does not make HTTP requests, test authorization, enumerate identifiers, infer successful exploitation, assign severity, or create confirmed findings. Route names are weak signals and can be misleading. A future AI layer may prioritize these links but must preserve evidence references and independently validate behavior within approved scope.
