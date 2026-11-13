# Assessment inquiry delivery

The public `/request-assessment` page is separate from the authenticated scanner.
`GET /contact/assessment/status` issues short-lived form verification;
`POST /contact/assessment` validates and forwards an inquiry through the
Replit-managed Resend connection. No findings tables, accounts, scanner logic,
or database migrations are involved.

## Required setup

- Connect the Resend **API** integration to this project.
- Verify a sending domain you control in Resend. A personal Gmail address can
  receive inquiries but cannot be used as a verified Resend sending domain.
- Set `ASSESSMENT_EMAIL_FROM` to a plain verified sender email address and
  `ASSESSMENT_EMAIL_TO` to the approved recipient address in the appropriate
  environment. These are server-side configuration, not browser inputs.
- Configure and test development first. Production configuration and publishing
  require separate owner approval; no production settings were changed here.
- A send-only integration is sufficient for forwarding, but cannot list domains
  or retrieve delivery events. Do not expand its permissions just to list them.

For development diagnostics only, `ASSESSMENT_EMAIL_FROM=onboarding@resend.dev`
can send to the email associated with the Resend account. The Preview form labels
this as test delivery and prefixes its email subject with `[TEST]`. This is not
a production workaround: production rejects `@resend.dev` senders even if these
values are accidentally copied across. Keep the normal email-client fallback
until a production sending domain or another approved delivery solution is ready.

Without both configured addresses the page explicitly says sending is unavailable
and offers the existing email-client fallback. A provider error returns 503, not
a success screen. The success message means Resend accepted the email, **not**
that a human saw it or that the destination inbox received it. Verify an approved
synthetic inquiry at the destination before claiming end-to-end delivery works.

## Protection and privacy

Only same-origin JSON submissions are accepted. The server revalidates required
fields, service choices, string bounds, email syntax, optional website and integer
server count. It never visits the submitted website or runs scans. A honeypot,
IP-bound signed verification with a two-second minimum/30-minute expiry, bounded
per-process IP rate limits and a global send budget reduce automated abuse.
Fixed server-side envelope addresses prevent arbitrary-recipient relay abuse.
Plain-text email avoids injecting submitted HTML.

Idempotency keys derive from signed verification; concurrent duplicate retries
share a send and retrying an uncertain provider result uses the same key.
Form values and provider error bodies are not logged; no local inquiry archive
or findings records are created. Resend and the destination mailbox retain
email under their own policies. Rate-limit state and request digests expire
in memory; raw IPs and full inquiry values are not retained in those maps.

These process-local rate limits are not a distributed CAPTCHA or durable queue.
Across restarts, old verification expires; an accepted email with a lost browser
response may need operator confirmation before a visitor submits a fresh form.
Apply edge-level abuse controls if intake is scaled or targeted. Do not weaken
scanner authorization or writer readiness to make inquiry intake available.

## Verification

Run `npm run typecheck` and `npm run test:assessments`.
The tests use a synthetic in-memory delivery adapter; they do not establish live
email receipt. A separate approved Preview submission and mailbox confirmation
are necessary for delivery acceptance. An inquiry never authorizes testing.
