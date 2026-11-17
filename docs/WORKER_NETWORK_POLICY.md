# Worker network destination gate

`backend/app/core/network_policy.py` is a pre-worker safety primitive. It:

- checks HTTP/HTTPS and the existing hostname allowlist;
- resolves DNS immediately before use and rejects the entire answer if any address is non-global (including loopback, private, link-local, multicast, reserved and unspecified ranges);
- returns normalized IP addresses so a future worker can pin the connection to those exact addresses rather than resolving the hostname again;
- re-runs the same checks for every redirect hop.

**Important limitations:** this module does not make network requests, follow redirects, enforce a firewall, or itself pin a socket. A worker must connect only to the returned IPs while preserving the original Host header and TLS SNI, disable automatic redirects, and call the gate again immediately before every connection. DNS must be re-resolved at dispatch and request time to reduce rebinding risk. Network egress controls remain mandatory; application checks are not a substitute for an isolated worker network.

No scan execution is enabled by this change. There is no worker or job dispatcher yet.
