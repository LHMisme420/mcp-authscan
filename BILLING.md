# VATA billing

VATA Pro is $99 USD/month. The current Stripe connection is a sandbox.
No paid feature limits have been invented: this change adds subscription
checkout, verified subscription status, and customer billing management.

## Run and check

- `npm run dev`: public Express/React application on port 5000, with a private
  Gunicorn scanning backend on loopback port 5001.
- `npm run build` and `npm run start`: publishing build and production startup.
- `npx tsc --noEmit` and `npm run test:billing`: type and billing-policy checks.
- `npm run seed:stripe`: creates/reuses the real $99 recurring sandbox price.
- `npx tsx scripts/verify-checkout.ts`: creates and expires a disposable sandbox
  checkout without paying.
- `npx tsx scripts/verify-account-flow.ts`: uses temporary development Clerk
  users, sandbox customers and a sandbox card to check account isolation,
  checkout ownership, portal access and verified subscription changes.
  This never charges real money and removes its temporary accounts afterwards.

## Storage and publishing

PostgreSQL holds verified account identities and customer relationships.
`stripe-replit-sync` owns the Stripe schema and validates webhook signatures.
The webhook receives raw bytes before JSON middleware. Returning to `/success`
alone never grants Pro.
Authenticated account checks refresh owned subscriptions through the Stripe
SDK to recover from delayed webhook delivery. Development-provider webhook
delivery was not observed; automatic delivery must be checked on the published URL.

The existing SQLite findings database has not been migrated or deleted.
It is still local storage: findings/history can be lost on Autoscale restarts
or republishing, and different instances can have different histories.
Back up published findings before republishing; the workspace backup is not
a backup of the published instance.

The publishing configuration is updated, but the user must click Publish.
Publish applies the development database schema changes to production through
Replit's database flow. Stripe copies the product/price catalog into the
production environment. Activate live payments through the Stripe setup before
expecting real customer charges.
