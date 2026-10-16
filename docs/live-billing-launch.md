# VATA live billing launch

## Approved scope

Pro is **$99 USD per month**, renewing until cancelled. It enables programmatic
API access, scheduling, and five seats including the owner and pending invites.
Manual scans and full findings history remain free. Existing findings and
organization ownership must not be moved, deleted, or reassigned.

## Defaults and safety

- Preview uses the existing Stripe test connector.
- Production billing is **disabled by default**.
- Production only enters live mode with `VATA_BILLING_MODE=live`.
- A live-mode connection in Preview, or a test-mode connection in live
  production, fails closed for paid actions; sign-in and free scans remain available.
- Live customer links are separate from historical/test customer links.
- A success/cancel URL never grants access or proves payment.
- `POST /api/test-checkout` is never available in production.
- Live checkout stays closed until signed catalog webhook delivery is recorded.
- Setup does not create a customer, subscription, or charge.

## Launch sequence (requires operator approval)

1. Verify the hosted test checkout and subscription lifecycle before accepting
   real customers. Unit tests alone do not prove Stripe-origin delivery.
2. Connect/authorize the **live Stripe account through Replit Publishing**.
   Keep Preview on the sandbox connection. Do not disconnect a healthy test
   connector or mix connector authentication with manually entered API keys.
3. Review the additive `migrations/live-billing.sql` and apply it to the billing
   database used by production. It creates only customer-ID mappings and signed
   event receipts. Subscription state remains owned by `stripe-replit-sync`.
4. In production environment settings (not `.replit`), explicitly set
   `VATA_BILLING_MODE=live` and set `PUBLIC_APP_URL` to the actual published
   origin obtained from Replit deployment metadata. Do not use a development URL.
   For the first launch, also set `VATA_PREPARE_LIVE_BILLING=1` to explicitly
   authorize the catalog/callback setup job in the published environment.
   Changing these settings is a separate launch action, not part of preparing code.
5. Publish only after approval. The signed callback is
   `POST <PUBLIC_APP_URL>/api/stripe/webhook`. Before setup is complete,
   checkout remains unavailable; free scans still work.
6. With the first-launch preparation switch enabled, the server starts HTTP
   first, then runs its compiled setup job using the production connector and
   database. No production shell or copied API keys are required. This job is
   not run unless both production live mode and the separate preparation switch
   are explicitly set. A setup failure never stops the web server.

   Alternatively, in a secure operator environment with **that production
   database and live connector authorization**, run:

   ```sh
   npm run billing:prepare-live -- --confirm-live-catalog
   ```

   This also requires `NODE_ENV=production`, `VATA_BILLING_MODE=live`, and the
   canonical `PUBLIC_APP_URL`. Do not point the Preview process at production
   credentials or its database just to run setup.

   The script checks live authorization and `charges_enabled`, registers only
   this app's callback, uses native Stripe schema migrations, and prepares the
   fixed catalog plus the cancellation/payment-method portal. It preserves all
   pre-existing callbacks and refuses to replace callbacks with missing secrets.
   It updates harmless product metadata and waits up to 90 seconds for a genuine
   signed live catalog event. Never paste the signing secret into chat.
7. After successful setup, remove `VATA_PREPARE_LIVE_BILLING` for subsequent
   releases so catalog delivery checks are not repeated on each restart.
   The running app retries optional billing initialization every minute. Verify
   `/api/billing/status` from a signed-in owner browser: `mode: "live"`,
   `available: true`, `checkoutReady: true`. The dashboard must say **Live billing**,
   not Test mode. Confirm checkout displays **$99 USD/month** before any purchase.
8. Only an authorized owner may choose to make a real paid purchase. Do not
   use Stripe test cards in live checkout. Verify Pro activation, invoice,
   portal access, cancellation at period end, and eventual entitlement expiry.

## If setup or delivery fails

New live checkout stays closed until the signed delivery gate is satisfied.
Check the exact endpoint in Stripe Workbench's delivery history. Verify the
production origin, enabled events, connector account/mode and published code.
Do not delete someone else's endpoints, rotate secrets, claim legacy customers,
or report signed local replays as actual Stripe delivery.

Before any customer has subscribed, reverting `VATA_BILLING_MODE` to `disabled`
returns production to its previous subscription-free behavior. Once real
subscriptions exist, disabling app billing **does not cancel Stripe charges**.
Do not use that switch as a cancellation mechanism; reconcile subscribers and
communicate billing changes before any shutdown. Backups are unchanged.
