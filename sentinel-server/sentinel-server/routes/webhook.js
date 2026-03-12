// routes/webhook.js — Stripe webhook events
import { Router }                                    from "express";
import Stripe                                        from "stripe";
import { nanoid }                                    from "nanoid";
import { createToken, deactivateByStripe, reactivateByStripe } from "../lib/db.js";
import { sendTokenEmail }                            from "../lib/email.js";

const router = Router();

router.post("/", async (req, res) => {
  const sig    = req.headers["stripe-signature"];
  const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch(e) {
    console.error("[Webhook] Signature failed:", e.message);
    return res.status(400).send(`Webhook Error: ${e.message}`);
  }

  console.log("[Webhook] Event:", event.type);

  switch (event.type) {

    case "checkout.session.completed": {
      // New subscriber — generate token and email it
      const session   = event.data.object;
      const email     = session.customer_details?.email || session.customer_email;
      const subId     = session.subscription;
      const tokenStr  = `SNT-${nanoid(4).toUpperCase()}-${nanoid(4).toUpperCase()}-${nanoid(4).toUpperCase()}`;

      try {
        await createToken(tokenStr, email, subId);
        await sendTokenEmail(email, tokenStr);
        console.log(`[Webhook] Token created for ${email}: ${tokenStr}`);
      } catch(e) {
        console.error("[Webhook] Token creation failed:", e.message);
      }
      break;
    }

    case "customer.subscription.deleted": {
      // Cancelled — deactivate token
      const sub = event.data.object;
      await deactivateByStripe(sub.id);
      console.log(`[Webhook] Deactivated token for sub: ${sub.id}`);
      break;
    }

    case "customer.subscription.updated": {
      const sub = event.data.object;
      if (sub.status === "active") {
        await reactivateByStripe(sub.id);
        console.log(`[Webhook] Reactivated token for sub: ${sub.id}`);
      } else if (["canceled","unpaid","past_due"].includes(sub.status)) {
        await deactivateByStripe(sub.id);
        console.log(`[Webhook] Deactivated (${sub.status}) for sub: ${sub.id}`);
      }
      break;
    }

    case "invoice.payment_failed": {
      const invoice = event.data.object;
      await deactivateByStripe(invoice.subscription);
      console.log(`[Webhook] Payment failed — deactivated sub: ${invoice.subscription}`);
      break;
    }
  }

  res.json({ received: true });
});

export default router;
