const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json;charset=UTF-8" }
  });

const corsHeaders = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "Content-Type"
};

function withCors(response) {
  const h = new Headers(response.headers);
  for (const [k,v] of Object.entries(corsHeaders)) h.set(k,v);
  return new Response(response.body, {status:response.status, headers:h});
}

function orderNumber() {
  const d = new Date();
  const stamp = d.toISOString().replace(/\D/g,"").slice(0,14);
  const rnd = crypto.randomUUID().slice(0,6).toUpperCase();
  return `PC-${stamp}-${rnd}`;
}

async function razorpayRequest(env, path, options={}) {
  const auth = btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
  const res = await fetch(`https://api.razorpay.com/v1${path}`, {
    ...options,
    headers: {
      "Authorization": `Basic ${auth}`,
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.description || "Razorpay API error");
  return data;
}

async function verifySignature(secret, orderId, paymentId, signature) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), {name:"HMAC", hash:"SHA-256"}, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(`${orderId}|${paymentId}`));
  const hex = [...new Uint8Array(sig)].map(b=>b.toString(16).padStart(2,"0")).join("");
  return hex === signature;
}

async function handleApi(request, env) {
  const url = new URL(request.url);

  if (request.method === "OPTIONS") return new Response(null,{status:204,headers:corsHeaders});

  if (url.pathname === "/api/config" && request.method === "GET") {
    return json({key_id: env.RAZORPAY_KEY_ID || ""});
  }

  if (url.pathname === "/api/create-order" && request.method === "POST") {
    let body;
    try { body = await request.json(); } catch { return json({error:"Invalid JSON"},400); }

    const amount = Number(body.amount);
    const c = body.customer || {};
    const items = Array.isArray(body.items) ? body.items : [];
    const paymentMethod = body.payment_method === "cod" ? "cod" : "online";

    if (!Number.isInteger(amount) || amount <= 0 || amount > 100000000) return json({error:"Invalid order amount"},400);
    if (!c.name || !/^\d{10}$/.test(String(c.mobile)) || !c.address || !c.city || !c.state || !/^\d{6}$/.test(String(c.pincode))) {
      return json({error:"Please provide valid customer details"},400);
    }
    if (!items.length) return json({error:"Cart is empty"},400);

    const orderNo = orderNumber();
    let razorOrderId = null;

    try {
      if (paymentMethod === "online") {
        const rp = await razorpayRequest(env, "/orders", {
          method:"POST",
          body:JSON.stringify({
            amount: amount * 100,
            currency:"INR",
            receipt: orderNo,
            notes:{order_number:orderNo}
          })
        });
        razorOrderId = rp.id;
      }

      await env.DB.prepare(`
        INSERT INTO orders
        (order_number, razorpay_order_id, customer_name, mobile, email, address, city, state, pincode,
         amount_paise, payment_method, payment_status, order_status, items_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `).bind(
        orderNo, razorOrderId, String(c.name), String(c.mobile), String(c.email||""),
        String(c.address), String(c.city), String(c.state), String(c.pincode),
        amount*100, paymentMethod,
        paymentMethod==="cod" ? "cod_pending" : "created",
        "new", JSON.stringify(items)
      ).run();

      return json({
        order_number:orderNo,
        amount:amount*100,
        currency:"INR",
        razorpay_order_id:razorOrderId
      });
    } catch (e) {
      return json({error:e.message || "Could not create order"},500);
    }
  }

  if (url.pathname === "/api/verify-payment" && request.method === "POST") {
    let body;
    try { body = await request.json(); } catch { return json({error:"Invalid JSON"},400); }

    if (!body.order_number || !body.razorpay_order_id || !body.razorpay_payment_id || !body.razorpay_signature) {
      return json({error:"Missing payment verification fields"},400);
    }

    const row = await env.DB.prepare(
      "SELECT * FROM orders WHERE order_number = ? AND razorpay_order_id = ?"
    ).bind(body.order_number, body.razorpay_order_id).first();

    if (!row) return json({error:"Order not found"},404);

    const valid = await verifySignature(
      env.RAZORPAY_KEY_SECRET,
      body.razorpay_order_id,
      body.razorpay_payment_id,
      body.razorpay_signature
    );
    if (!valid) return json({error:"Invalid payment signature"},400);

    await env.DB.prepare(`
      UPDATE orders
      SET razorpay_payment_id=?, razorpay_signature=?, payment_status='paid',
          order_status='confirmed', updated_at=datetime('now')
      WHERE order_number=?
    `).bind(
      body.razorpay_payment_id, body.razorpay_signature, body.order_number
    ).run();

    return json({ok:true,order_number:body.order_number});
  }

  if (url.pathname === "/api/webhook" && request.method === "POST") {
    const raw = await request.text();
    const signature = request.headers.get("x-razorpay-signature") || "";
    if (!env.RAZORPAY_WEBHOOK_SECRET) return json({error:"Webhook secret not configured"},500);

    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw", enc.encode(env.RAZORPAY_WEBHOOK_SECRET),
      {name:"HMAC",hash:"SHA-256"}, false, ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC",key,enc.encode(raw));
    const expected = [...new Uint8Array(sig)].map(b=>b.toString(16).padStart(2,"0")).join("");
    if (expected !== signature) return json({error:"Invalid webhook signature"},400);

    let event;
    try { event=JSON.parse(raw); } catch { return json({error:"Invalid webhook JSON"},400); }

    if (event.event === "order.paid") {
      const order = event.payload?.order?.entity;
      const payment = event.payload?.payment?.entity;
      if (order?.receipt) {
        await env.DB.prepare(`
          UPDATE orders
          SET payment_status='paid', order_status='confirmed',
              razorpay_payment_id=COALESCE(?,razorpay_payment_id),
              updated_at=datetime('now')
          WHERE order_number=?
        `).bind(payment?.id || null, order.receipt).run();
      }
    }
    return json({ok:true});
  }

  return json({error:"Not found"},404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try { return withCors(await handleApi(request, env)); }
      catch (e) { return withCors(json({error:e.message || "Server error"},500)); }
    }
    return env.ASSETS.fetch(request);
  }
};
