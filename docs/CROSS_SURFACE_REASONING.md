# Cross-Surface Reasoning

The cross-surface engine links only already observed passive URL records and the deterministic business-logic profile.

## Relationships
- Authentication-related route + object-resource route on the same normalized host.
- Authentication-related route + potentially sensitive action route on the same host.
- Object-resource route + potentially sensitive action route on the same host.

## Evidence and limitations
Every link retains source observation IDs and validation questions. A shared host and route-name co-occurrence do **not** establish that endpoints share authentication middleware, authorization rules, roles, ownership, workflow order, or exploitable behavior. No HTTP method is inferred. No request, DNS lookup, crawl, active test, or model call is performed by this module. Every result remains `requires_independent_validation`.

The caller must supply an ownership-checked analysis context. This module is deterministic and has no API route or automatic scan invocation.
