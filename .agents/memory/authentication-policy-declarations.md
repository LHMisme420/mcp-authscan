---
name: Authentication policy declarations
description: Keep expected authorization requirements separate from immutable signed scan evidence.
---

Authorization requirements belong in the caller's policy file, not in new fields
added to a signed report. An optional declaration must not change existing gate
output or exit behavior when absent or disabled.

**Why:** the user explicitly required the declaration to remain outside the signed
artifact and prohibited changes to report hashes, signatures and schemes for this
policy feature.

**How to apply:** compare declared requirements with existing positive resource
observations. Do not infer anonymous access from public OAuth metadata, an
excluded check or missing coverage, and do not change report serialization to
implement a policy decision.
