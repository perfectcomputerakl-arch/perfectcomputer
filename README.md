# PERFECT COMPUTER — Real Checkout Setup

This package upgrades the existing frontend demo to a Cloudflare Worker + D1 checkout.

## Files
- index.html — checkout form + Razorpay/COD frontend
- src/index.js — Cloudflare Worker API
- schema.sql — D1 orders table
- wrangler.toml — Worker/D1 configuration

## Cloudflare setup
1. Create a D1 database named `perfectcomputer-db`.
2. Copy its Database ID.
3. Replace `PASTE_YOUR_D1_DATABASE_ID_HERE` in wrangler.toml.
4. Run the SQL in schema.sql against the D1 database.
5. In Worker Settings → Variables and Secrets, add:
   - RAZORPAY_KEY_ID = your Razorpay Key ID (test key first)
   - RAZORPAY_KEY_SECRET = your Razorpay Key Secret
   - RAZORPAY_WEBHOOK_SECRET = a webhook secret you create
6. Deploy with the existing command: `npx wrangler deploy`.
7. In Razorpay Dashboard, create a webhook pointing to:
   `https://YOUR-SITE.workers.dev/api/webhook`
   Subscribe to `order.paid`.
8. Test in Razorpay Test Mode before switching to Live Mode.

IMPORTANT:
- Never put RAZORPAY_KEY_SECRET in index.html.
- Never send the Secret Key in chat.
- Use Razorpay Test Mode first.
