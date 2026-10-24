---
name: Preview HTTP routing
description: A healthy app can appear broken when Preview routes to the websocket listener.
---

Verify the proxied Preview domain as well as localhost or a port-specific
screenshot before diagnosing a Python runtime failure.

**Why:** The app rendered normally and local health returned 200 while the
main Preview domain returned 426: its external HTTP entrypoint had been mapped
to Vite's websocket listener instead of the application.

**How to apply:** Keep the public HTTP mapping on the application listener,
not the HMR listener; preserve the private scanner's loopback-only binding.
Use validated Replit configuration replacement, restart once, and check health
through the actual Preview domain. A port-specific screenshot alone does not
verify the external mapping.

A validated replacement reported success and briefly produced working root
routing, but the old mappings later reappeared without further app edits.
The port-specific Preview remained healthy. Recheck persistence before claiming
the default URL is fixed; if platform-managed mappings keep reverting, stop
repeating source/config edits and use the Networking controls to update the
authoritative forwarding setting. Sharing development websocket upgrades with
the application's HTTP server avoids requiring a second public listener, but
does not by itself remove stale platform forwarding metadata.
