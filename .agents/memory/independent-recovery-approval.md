---
name: Independent recovery approval
description: Scope of owner approval for off-project disaster recovery and fixture auth lessons.
---

The owner approved an encrypted off-project backup policy under a separate
owner-controlled account: 30 daily recovery points and 12 monthly points,
covering account ownership and findings together, plus a synthetic rehearsal.
The proposed targets are 24-hour data loss and four-hour recovery, not guarantees.
The owner subsequently approved separate owner-controlled Google Cloud storage
in the US multi-region, variable operating costs, Secret Manager plus a separate
offline key copy, initial and recurring daily sensitive exports, and a separate
isolated live recovery rehearsal. The owner then explicitly deferred live backups
and requested that the website proceed without them.

**Why:** After the setup became difficult, the owner said backups were not needed
right now and asked to get the site online without them.

**How to apply:** Do not activate live exports, uploads, scheduling, or a live
rehearsal unless the owner explicitly resumes backup setup. Do not describe a
local encrypted file or a successful fixture restore as operational independent
live protection. Production replacement remains outside the approved scope.

Scaled synthetic timings are local baselines, not evidence that the recovery
target holds for production data or an off-site provider path.

**Why:** Synthetic database volumes and loopback transfer do not reproduce
production concurrency, storage behavior, or remote network conditions.

**How to apply:** Keep synthetic measurements clearly labeled and do not treat
them as an operational RTO guarantee. Obtain separate approval before a live
production-sized rehearsal.

Offline Clerk cookie fixtures need the development browser cookie and client
update timestamp as well as an RSA-signed session and the fixture public key.

**Why:** A correctly signed cookie alone was reported signed-out by Clerk's
development-browser checks, even though token signature verification was valid.

**How to apply:** Supply synthetic development-browser/client cookies in fixtures;
never bypass the app's auth or use production credentials to make rehearsals pass.
