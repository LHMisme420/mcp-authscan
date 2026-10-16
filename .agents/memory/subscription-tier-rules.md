---
name: Workspace capacity and scheduling
description: Owner-approved team capacity, usage periods and always-on hosting choice.
---

The five-seat organization capacity includes the owner and pending invitations.
Scan usage periods use UTC calendar months. These operational conventions are
independent of payments. The owner's subsequent restoration of paid advanced
features does not reinstate Free/Pro scan quotas or history restrictions.

**Why:** The owner specified five team seats and monthly scan accounting;
removing payments should not remove team-capacity safeguards.

**How to apply:** Reserve seats for pending invitations to avoid overbooking.
Do not reintroduce subscription-based scan quotas or hide older history.

The user selected always-on Reserved VM hosting for scheduled scans.

**Why:** They want unattended scans even when nobody is visiting, and selected
Reserved VM after being told idle Autoscale can sleep and hosting costs may change.

**How to apply:** Keep the next publishing target on Reserved VM unless they
change direction. Do not present a preview worker as proof the live deployment
has been republished. Do not imply that always-on hosting makes local SQLite
files durable across replacement deployments.
