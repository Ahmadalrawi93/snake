# Scanner Engine — Not Yet Implemented

Future adapters will wrap established tools behind a common job contract. Every job must include project and authorization IDs, immutable scope snapshot, allowed operation class, rate and concurrency limits, timeout/cancellation support, structured output, and audit event IDs.

Do not add arbitrary URL scanning or shell execution endpoints. Tool execution belongs in an isolated worker with outbound network policy and scope checks repeated at execution time.
