---
name: Uploaded report verification
description: Keep offline report integrity checking separate from scan reproduction and provenance claims.
---

Use the scanner's actual canonical hash function for uploaded report verification; never approximate a legacy scheme or initiate a target scan.

**Why:** The owner explicitly required the CLI's computation, no outbound target requests, no accounts and no report storage or report-content logging.

**How to apply:** Unsupported formats must be reported as unreadable rather than silently mapped to a different scheme. A matching unkeyed digest proves consistency with the stored hash, not producer identity, authorization, server security or that nobody edited and rehashed the report.
