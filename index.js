const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json;charset=UTF-8" }
  });

const corsHeaders = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "Content-Type, Authorization"
};

function withCors(response) {
  const h = new Headers(response.headers);
  for (const [k, v] of Object.entries(corsHeaders)) h.set(k, v);
  return new Response(response.body, {
    status: response.status,
    headers: h
  });
}

function orderNumber() {
  const d = new Date();
  const stamp = d.toISOString().replace(/\D/g, "").slice(0, 14);
  const rnd = crypto.randomUUID().slice(0, 6).toUpperCase();
  return `PC-${stamp}-${rnd}`;
}

async function razorpayRequest(env, path, options = {}) {
  const auth = btoa(
    `${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`
  );

  const res = await fetch(`https://api.razorpay.com/v1${path}`, {
    ...options,
    headers: {
      "Authorization": `Basic ${auth}`,
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  const data = await res.json();

  if (!res.ok) {
    throw new Error(
      data.error?.description || "Razorpay API error"
    );
  }

  return data;
}

async function verifySignature(
  secret,
  orderId,
  paymentId,
  signature
) {
  const enc = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    enc.encode(`${orderId}|${paymentId}`)
  );

  const hex = [...new Uint8Array(sig)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  return hex === signature;
}


/* =========================================================
   ADMIN AUTHENTICATION
   ========================================================= */

function requireAdmin(request, env) {
  const auth = request.headers.get("Authorization") || "";

  if (!auth.startsWith("Bearer ")) {
    return false;
  }

  const token = auth.slice(7).trim();

  if (!env.ADMIN_TOKEN || !token) {
    return false;
  }

  return token === env.ADMIN_TOKEN;
}


/* =========================================================
   ADMIN — GET ORDERS
   ========================================================= */

async function adminOrders(request, env) {

  if (!requireAdmin(request, env)) {
    return json({
      error: "Unauthorized"
    }, 401);
  }

  const result = await env.DB.prepare(`
    SELECT
      id,
      order_number,

      razorpay_order_id,
      razorpay_payment_id,

      customer_name,
      mobile,
      email,

      address,
      city,
      state,
      pincode,

      amount_paise,

      payment_method,
      payment_status,
      order_status,

      items_json,

      courier_name,
      tracking_number,
      tracking_url,
      shipped_at,
      delivered_at,

      created_at,
      updated_at

    FROM orders

    ORDER BY id DESC

    LIMIT 500
  `).all();

  return json({
    ok: true,
    orders: result.results || []
  });
}

/* =========================================================
   ADMIN — UPDATE ORDER STATUS
   ========================================================= */

async function adminOrderStatus(request, env) {

  if (!requireAdmin(request, env)) {
    return json({
      error: "Unauthorized"
    }, 401);
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json({
      error: "Invalid JSON"
    }, 400);
  }

  const orderNumberValue =
    String(body.order_number || "").trim();

  const status =
    String(body.order_status || "")
      .trim()
      .toLowerCase();


  const allowed = [
    "new",
    "confirmed",
    "shipped",
    "delivered",
    "cancelled"
  ];


  if (
    !orderNumberValue ||
    !allowed.includes(status)
  ) {
    return json({
      error: "Invalid order number or status"
    }, 400);
  }


  let extraSQL = "";
  let binds = [status];


  if (status === "shipped") {

    extraSQL = `,
      shipped_at = datetime('now')
    `;

  }


  if (status === "delivered") {

    extraSQL = `,
      delivered_at = datetime('now')
    `;

  }


  const result = await env.DB.prepare(`
    UPDATE orders

    SET
      order_status = ?,
      updated_at = datetime('now')
      ${extraSQL}

    WHERE order_number = ?

  `).bind(
    ...binds,
    orderNumberValue
  ).run();


  if (!result.meta?.changes) {

    return json({
      error: "Order not found"
    }, 404);

  }


  return json({
    ok: true,
    order_number: orderNumberValue,
    order_status: status
  });

}
/* =========================================================
   ADMIN — UPDATE SHIPPING / TRACKING
   ========================================================= */

async function adminShipping(request, env) {

  if (!requireAdmin(request, env)) {
    return json({
      error: "Unauthorized"
    }, 401);
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json({
      error: "Invalid JSON"
    }, 400);
  }

  const orderNumberValue =
    String(body.order_number || "").trim();

  const courierName =
    String(body.courier_name || "").trim();

  const trackingNumber =
    String(body.tracking_number || "").trim();

  const trackingUrl =
    String(body.tracking_url || "").trim();


  if (!orderNumberValue) {
    return json({
      error: "Order number required"
    }, 400);
  }


  const result = await env.DB.prepare(`
    UPDATE orders

    SET
      courier_name = ?,
      tracking_number = ?,
      tracking_url = ?,
      updated_at = datetime('now')

    WHERE order_number = ?

  `).bind(
    courierName,
    trackingNumber,
    trackingUrl,
    orderNumberValue
  ).run();


  if (!result.meta?.changes) {

    return json({
      error: "Order not found"
    }, 404);

  }


  return json({
    ok: true,
    order_number: orderNumberValue,
    courier_name: courierName,
    tracking_number: trackingNumber,
    tracking_url: trackingUrl
  });

}
/* =========================================================
   MAIN API HANDLER
   ========================================================= */

async function handleApi(request, env) {

  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders
    });
  }


  /* ================= CONFIG ================= */

  if (
    url.pathname === "/api/config" &&
    request.method === "GET"
  ) {
    return json({
      key_id: env.RAZORPAY_KEY_ID || ""
    });
  }


  /* ================= CREATE ORDER ================= */

  if (
    url.pathname === "/api/create-order" &&
    request.method === "POST"
  ) {

    let body;

    try {
      body = await request.json();
    } catch {
      return json({
        error: "Invalid JSON"
      }, 400);
    }

    const amount = Number(body.amount);
    const c = body.customer || {};
    const items = Array.isArray(body.items)
      ? body.items
      : [];

    const paymentMethod =
      body.payment_method === "cod"
        ? "cod"
        : "online";

    if (
      !Number.isInteger(amount) ||
      amount <= 0 ||
      amount > 100000000
    ) {
      return json({
        error: "Invalid order amount"
      }, 400);
    }

    if (
      !c.name ||
      !/^\d{10}$/.test(String(c.mobile)) ||
      !c.address ||
      !c.city ||
      !c.state ||
      !/^\d{6}$/.test(String(c.pincode))
    ) {
      return json({
        error: "Please provide valid customer details"
      }, 400);
    }

    if (!items.length) {
      return json({
        error: "Cart is empty"
      }, 400);
    }

    const orderNo = orderNumber();

    let razorOrderId = null;

    try {

      if (paymentMethod === "online") {

        const rp = await razorpayRequest(
          env,
          "/orders",
          {
            method: "POST",

            body: JSON.stringify({
              amount: amount * 100,
              currency: "INR",
              receipt: orderNo,
              notes: {
                order_number: orderNo
              }
            })
          }
        );

        razorOrderId = rp.id;
      }

      await env.DB.prepare(`
        INSERT INTO orders
        (
          order_number,
          razorpay_order_id,
          customer_name,
          mobile,
          email,
          address,
          city,
          state,
          pincode,
          amount_paise,
          payment_method,
          payment_status,
          order_status,
          items_json,
          created_at
        )
        VALUES (
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now')
        )
      `).bind(

        orderNo,
        razorOrderId,
        String(c.name),
        String(c.mobile),
        String(c.email || ""),
        String(c.address),
        String(c.city),
        String(c.state),
        String(c.pincode),
        amount * 100,
        paymentMethod,

        paymentMethod === "cod"
          ? "cod_pending"
          : "created",

        "new",

        JSON.stringify(items)

      ).run();

      return json({
        order_number: orderNo,
        amount: amount * 100,
        currency: "INR",
        razorpay_order_id: razorOrderId
      });

    } catch (e) {

      return json({
        error:
          e.message ||
          "Could not create order"
      }, 500);
    }
  }


  /* ================= VERIFY PAYMENT ================= */

  if (
    url.pathname === "/api/verify-payment" &&
    request.method === "POST"
  ) {

    let body;

    try {
      body = await request.json();
    } catch {
      return json({
        error: "Invalid JSON"
      }, 400);
    }

    if (
      !body.order_number ||
      !body.razorpay_order_id ||
      !body.razorpay_payment_id ||
      !body.razorpay_signature
    ) {
      return json({
        error: "Missing payment verification fields"
      }, 400);
    }

    const row = await env.DB.prepare(
      `SELECT *
       FROM orders
       WHERE order_number = ?
       AND razorpay_order_id = ?`
    ).bind(
      body.order_number,
      body.razorpay_order_id
    ).first();

    if (!row) {
      return json({
        error: "Order not found"
      }, 404);
    }

    const valid = await verifySignature(
      env.RAZORPAY_KEY_SECRET,
      body.razorpay_order_id,
      body.razorpay_payment_id,
      body.razorpay_signature
    );

    if (!valid) {
      return json({
        error: "Invalid payment signature"
      }, 400);
    }

    await env.DB.prepare(`
      UPDATE orders
      SET
        razorpay_payment_id = ?,
        razorpay_signature = ?,
        payment_status = 'paid',
        order_status = 'confirmed',
        updated_at = datetime('now')
      WHERE order_number = ?
    `).bind(
      body.razorpay_payment_id,
      body.razorpay_signature,
      body.order_number
    ).run();

    return json({
      ok: true,
      order_number: body.order_number
    });
  }


  /* ================= RAZORPAY WEBHOOK ================= */

  if (
    url.pathname === "/api/webhook" &&
    request.method === "POST"
  ) {

    const raw = await request.text();

    const signature =
      request.headers.get(
        "x-razorpay-signature"
      ) || "";

    if (!env.RAZORPAY_WEBHOOK_SECRET) {
      return json({
        error: "Webhook secret not configured"
      }, 500);
    }

    const enc = new TextEncoder();

    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(
        env.RAZORPAY_WEBHOOK_SECRET
      ),
      {
        name: "HMAC",
        hash: "SHA-256"
      },
      false,
      ["sign"]
    );

    const sig = await crypto.subtle.sign(
      "HMAC",
      key,
      enc.encode(raw)
    );

    const expected = [
      ...new Uint8Array(sig)
    ]
      .map(b =>
        b.toString(16).padStart(2, "0")
      )
      .join("");

    if (expected !== signature) {
      return json({
        error: "Invalid webhook signature"
      }, 400);
    }

    let event;

    try {
      event = JSON.parse(raw);
    } catch {
      return json({
        error: "Invalid webhook JSON"
      }, 400);
    }

    if (event.event === "order.paid") {

      const order =
        event.payload?.order?.entity;

      const payment =
        event.payload?.payment?.entity;

      if (order?.receipt) {

        await env.DB.prepare(`
          UPDATE orders
          SET
            payment_status = 'paid',
            order_status = 'confirmed',
            razorpay_payment_id =
              COALESCE(?, razorpay_payment_id),
            updated_at = datetime('now')
          WHERE order_number = ?
        `).bind(
          payment?.id || null,
          order.receipt
        ).run();
      }
    }

    return json({
      ok: true
    });
  }


  /* =========================================================
     ADMIN API ROUTES
     ========================================================= */

  if (
    url.pathname === "/api/admin/orders" &&
    request.method === "GET"
  ) {
    return adminOrders(request, env);
  }
if (
  url.pathname === "/api/admin/shipping" &&
  request.method === "POST"
) {
  return adminShipping(request, env);
}

  if (
    url.pathname === "/api/admin/order-status" &&
    request.method === "POST"
  ) {
    return adminOrderStatus(request, env);
  }


  return json({
    error: "Not found"
  }, 404);
}


/* =========================================================
   WORKER
   ========================================================= */

export default {

  async fetch(request, env) {

    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {

      try {

        return withCors(
          await handleApi(
            request,
            env
          )
        );

      } catch (e) {

        return withCors(
          json({
            error:
              e.message ||
              "Server error"
          }, 500)
        );
      }
    }

    return env.ASSETS.fetch(request);
  }
};
