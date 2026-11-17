---
name: Uploaded report verification
description: Keep offline report integrity checking separate from scan reproduction and provenance claims.
---

Use the scanner's actual canonical hash function for uploaded report verification; never approximate a legacy scheme or initiate a target scan.

**Why:** The owner explicitly required the CLI's computation, no outbound target requests, no accounts and no report storage or report-content logging.

**How to apply:** Unsupported formats must be reported as unreadable rather than silently mapped to a different scheme. A matching unkeyed digest proves consistency with the stored hash, not producer identity, authorization, server security or that nobody edited and rehashed the report.

Keep integrity and authenticity independent. Verify detached Ed25519 signatures only against explicitly published public keys and exactly the CLI's canonical bytes. Private signing keys must stay outside all repositories and the website runtime.

**Why:** The owner reserved signing for the CLI. After a runner-only proof, they clarified that a runner home directory is not acceptable long-term signing-key custody. Production signing must use a replacement generated on an owner-controlled machine; only its public key and key_id may cross into the website.

**How to apply:** Publish only explicitly authorized public identities. Report unsigned, unknown-key, malformed and invalid-signature states honestly; do not infer signature validity from a matching hash, or hash integrity from a valid signature. Sign only schema-3 CLI JSON; PDF output points to its JSON hash and signing key_id rather than signing layout bytes. Do not sign a second, incompatible format.

Keep published key_ids append-only; do not remove historical public keys.

**Why:** The owner explicitly requires old reports not to turn into UNKNOWN KEY when signing identities change.

**How to apply:** Add replacement public identities without deleting existing ones. Historical key retention does not establish current trust or cure compromised key custody; treat revocation/trust status as a separate decision.

Preserve uploaded JSON text rather than parsing and reserializing it in JavaScript before verification.

**Why:** Python's existing canonical serializer distinguishes a floating-point `1.0` from integer `1`. A JavaScript JSON round trip can normalize the former to the latter and invalidate a legitimate signature even when a test intended to change only the stored digest.

**How to apply:** Keep the raw-text upload path. For independence tests, replace only the intended field in the original JSON text; do not change canonicalization to accommodate JavaScript numeric normalization.
