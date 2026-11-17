# Analysis Evidence Redaction

Before external provider transmission, the adapter creates a redacted copy of the analysis context. The persisted/original context is not mutated and observation IDs remain unchanged.

The current deterministic patterns cover common bearer/basic credentials, JWT-like tokens, AWS access-key identifiers, PEM private-key blocks, credential-like key/value pairs, and sensitive URL query parameter values.

This is defense in depth, not a complete DLP system. Unknown encodings, proprietary secret formats, credentials embedded in unusual structures, and sensitive personal data may remain. Production use still requires explicit data classification, user consent, retention controls, and a review of what evidence may leave the environment.
