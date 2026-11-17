---
name: Uploaded report verification
description: Keep offline report integrity checking separate from scan reproduction and provenance claims.
---

Use the scanner's actual canonical hash function for uploaded report verification; never approximate a legacy scheme or initiate a target scan.

**Why:** The owner explicitly required the CLI's computation, no outbound target requests, no accounts and no report storage or report-content logging.

**How to apply:** Unsupported formats must be reported as unreadable rather than silently mapped to a different scheme. A matching unkeyed digest proves consistency with the stored hash, not producer identity, authorization, server security or that nobody edited and rehashed the report.

Keep integrity and authenticity independent. Verify detached Ed25519 signatures only against explicitly published public keys and exactly the CLI's canonical bytes; never generate or handle a private signing key in this project.

**Why:** The owner explicitly reserved signing for the package on their own machine, with only the public half supplied to the site. No signer identity may be invented.

**How to apply:** Leave the published key list empty until the owner provides a legitimate public key. Report unsigned, unknown-key, malformed and invalid-signature states honestly; do not infer signature validity from a matching hash, or hash integrity from a valid signature.
