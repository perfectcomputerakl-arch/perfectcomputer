const corsHeaders = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS",
  "access-control-allow-headers": "Content-Type, Authorization"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...corsHeaders
    }
  });
}

function withCors(response) {
  const headers = new Headers(response.headers);

  Object.entries(corsHeaders).forEach(([key, value]) => {
    headers.set(key, value);
  });

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function orderNumber() {
  const d = new Date();

  const pad = n => String(n).padStart(2, "0");

  const stamp =
    d.getFullYear() +
    pad(d.getMonth() + 1) +
    pad(d.getDate()) +
    pad(d.getHours()) +
    pad(d.getMinutes()) +
    pad(d.getSeconds());

  const suffix = Math.random()
    .toString(36)
    .slice(2, 6)
    .toUpperCase();

  return `PC-${stamp}-${suffix}`;
}

async function razorpayRequest(env, path, options = {}) {
  const keyId = env.RAZORPAY_KEY_ID;
  const keySecret = env.RAZORPAY_KEY_SECRET;

  if (!keyId || !keySecret) {
    throw new Error("Razorpay credentials are not configured");
  }

  const auth = btoa(`${keyId}:${keySecret}`);

  const response = await fetch(
    `https://api.razorpay.com/v1${path}`,
    {
      ...options,
      headers: {
        "content-type": "application/json",
        "authorization": `Basic ${auth}`,
        ...(options.headers || {})
      }
    }
  );

  const text = await response.text();

  let data;

  try {
    data = JSON.parse(text);
  } catch {
    data = { error: text };
  }

  if (!response.ok) {
    throw new Error(
      data?.error?.description ||
      data?.error?.reason ||
      data?.error ||
      `Razorpay HTTP ${response.status}`
    );
  }

  return data;
}

async function verifyRazorpaySignature(
  orderId,
  paymentId,
  signature,
  secret
) {
  const message = `${orderId}|${paymentId}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(message)
  );

  const expected = [...new Uint8Array(signatureBuffer)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  return expected === String(signature || "").toLowerCase();
}

function getAdminToken(request, env) {
  const headerToken =
    request.headers.get("authorization") || "";

  if (headerToken.startsWith("Bearer ")) {
    return headerToken.slice(7).trim();
  }

  const url = new URL(request.url);

  return String(
    url.searchParams.get("token") || ""
  ).trim();
}

function requireAdmin(request, env) {
  const expected =
    String(env.ADMIN_TOKEN || "").trim();

  const actual =
    getAdminToken(request, env);

  if (!expected || !actual || actual !== expected) {
    return json({
      error: "Unauthorized"
    }, 401);
  }

  return null;
}

function productAdminData(body = {}) {
  const name =
    String(body.name || "").trim();

  const brand =
    String(body.brand || "").trim();

  const category =
    String(body.category || "").trim();

  const sku =
    String(body.sku || "").trim();

  const description =
    String(body.description || "").trim();

  const imageUrl =
    String(body.image_url || "").trim();

  const status =
    String(body.status || "active")
      .trim()
      .toLowerCase();

  const price = Number(body.price);
  const mrp = Number(body.mrp);
  const stockQty = Number(body.stock_qty);

  if (!name || !category) {
    throw new Error(
      "Product name and category are required"
    );
  }

  if (!Number.isFinite(price) || price < 0) {
    throw new Error(
      "Invalid selling price"
    );
  }

  if (!Number.isFinite(mrp) || mrp < 0) {
    throw new Error(
      "Invalid MRP"
    );
  }

  if (
    !Number.isInteger(stockQty) ||
    stockQty < 0
  ) {
    throw new Error(
      "Invalid stock quantity"
    );
  }

  if (
    !["active", "inactive"].includes(status)
  ) {
    throw new Error(
      "Invalid product status"
    );
  }

  if (
    imageUrl &&
    !/^https?:\/\//i.test(imageUrl)
  ) {
    throw new Error(
      "Image URL must start with http:// or https://"
    );
  }

  return {
    name,
    brand,
    category,
    sku,
    description,
    image_url: imageUrl,

    price_paise:
      Math.round(price * 100),

    mrp_paise:
      Math.round(mrp * 100),

    stock_qty:
      stockQty,

    status
  };
}

async function publicProducts(request, env) {
  const result =
    await env.DB.prepare(`
      SELECT
        id,
        name,
        brand,
        category,
        sku,
        description,
        image_url,
        price_paise,
        mrp_paise,
        stock_qty,
        status,
        created_at,
        updated_at
      FROM products
      WHERE status = 'active'
      ORDER BY id DESC
    `).all();

  return json({
    ok: true,
    products: result.results || []
  });
}

async function adminProducts(request, env) {
  const authError =
    requireAdmin(request, env);

  if (authError) {
    return authError;
  }

  const result =
    await env.DB.prepare(`
      SELECT
        id,
        name,
        brand,
        category,
        sku,
        description,
        image_url,
        price_paise,
        mrp_paise,
        stock_qty,
        status,
        created_at,
        updated_at
      FROM products
      ORDER BY id DESC
    `).all();

  return json({
    ok: true,
    products: result.results || []
  });
}

async function createProduct(request, env) {
  const authError =
    requireAdmin(request, env);

  if (authError) {
    return authError;
  }

  try {
    const body =
      await request.json();

    const p =
      productAdminData(body);

    const result =
      await env.DB.prepare(`
        INSERT INTO products (
          name,
          brand,
          category,
          sku,
          description,
          image_url,
          price_paise,
          mrp_paise,
          stock_qty,
          status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        p.name,
        p.brand,
        p.category,
        p.sku,
        p.description,
        p.image_url,
        p.price_paise,
        p.mrp_paise,
        p.stock_qty,
        p.status
      ).run();

    return json({
      ok: true,
      id:
        result.meta?.last_row_id || null,
      message:
        "Product created successfully"
    }, 201);

  } catch (error) {
    return json({
      error:
        error?.message ||
        "Could not create product"
    }, 400);
  }
}

async function updateProduct(request, env) {
  const authError =
    requireAdmin(request, env);

  if (authError) {
    return authError;
  }

  try {
    const body =
      await request.json();

    const id =
      Number(body.id);

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return json({
        error: "Invalid product ID"
      }, 400);
    }

    const p =
      productAdminData(body);

    const result =
      await env.DB.prepare(`
        UPDATE products
        SET
          name = ?,
          brand = ?,
          category = ?,
          sku = ?,
          description = ?,
          image_url = ?,
          price_paise = ?,
          mrp_paise = ?,
          stock_qty = ?,
          status = ?,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(
        p.name,
        p.brand,
        p.category,
        p.sku,
        p.description,
        p.image_url,
        p.price_paise,
        p.mrp_paise,
        p.stock_qty,
        p.status,
        id
      ).run();

    if (!result.meta?.changes) {
      return json({
        error: "Product not found"
      }, 404);
    }

    return json({
      ok: true,
      message:
        "Product updated successfully"
    });

  } catch (error) {
    return json({
      error:
        error?.message ||
        "Could not update product"
    }, 400);
  }
}

async function deleteProduct(request, env) {
  const authError =
    requireAdmin(request, env);

  if (authError) {
    return authError;
  }

  try {
    const body =
      await request.json();

    const id =
      Number(body.id);

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return json({
        error: "Invalid product ID"
      }, 400);
    }

    const result =
      await env.DB.prepare(`
        DELETE FROM products
        WHERE id = ?
      `).bind(id).run();

    if (!result.meta?.changes) {
      return json({
        error: "Product not found"
      }, 404);
    }

    return json({
      ok: true,
      message:
        "Product deleted successfully"
    });

  } catch (error) {
    return json({
      error:
        error?.message ||
        "Could not delete product"
    }, 400);
  }
}async function adminOrders(request, env) {
  const authError =
    requireAdmin(request, env);

  if (authError) {
    return authError;
  }

  const result =
    await env.DB.prepare(`
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

  const orders =
    (result.results || []).map(row => {
      let items = [];

      try {
        items =
          JSON.parse(
            row.items_json || "[]"
          );

        if (!Array.isArray(items)) {
          items = [];
        }
      } catch {
        items = [];
      }

      return {
        ...row,
        amount_paise:
          Number(row.amount_paise || 0),
        items
      };
    });

  return json({
    ok: true,
    orders
  });
}


async function adminOrderStatus(request, env) {
  const authError =
    requireAdmin(request, env);

  if (authError) {
    return authError;
  }

  try {
    const body =
      await request.json();

    const orderNumberValue =
      String(
        body.order_number || ""
      ).trim();

    const orderStatus =
      String(
        body.order_status || ""
      ).trim().toLowerCase();

    if (!orderNumberValue) {
      return json({
        error:
          "Order number is required"
      }, 400);
    }

    if (
      ![
        "new",
        "confirmed",
        "shipped",
        "delivered"
      ].includes(orderStatus)
    ) {
      return json({
        error:
          "Invalid order status"
      }, 400);
    }

    let sql = `
      UPDATE orders
      SET
        order_status = ?,
        updated_at = CURRENT_TIMESTAMP
    `;

    const params = [
      orderStatus
    ];

    if (
      orderStatus === "shipped"
    ) {
      sql += `,
        shipped_at = CURRENT_TIMESTAMP
      `;
    }

    if (
      orderStatus === "delivered"
    ) {
      sql += `,
        delivered_at = CURRENT_TIMESTAMP
      `;
    }

    sql += `
      WHERE order_number = ?
    `;

    params.push(
      orderNumberValue
    );

    const result =
      await env.DB
        .prepare(sql)
        .bind(...params)
        .run();

    if (!result.meta?.changes) {
      return json({
        error:
          "Order not found"
      }, 404);
    }

    return json({
      ok: true,
      message:
        "Order status updated"
    });

  } catch (error) {
    return json({
      error:
        error?.message ||
        "Could not update order status"
    }, 400);
  }
}


async function adminShipping(request, env) {
  const authError =
    requireAdmin(request, env);

  if (authError) {
    return authError;
  }

  try {
    const body =
      await request.json();

    const orderNumberValue =
      String(
        body.order_number || ""
      ).trim();

    const courierName =
      String(
        body.courier_name || ""
      ).trim();

    const trackingNumber =
      String(
        body.tracking_number || ""
      ).trim();

    const trackingUrl =
      String(
        body.tracking_url || ""
      ).trim();

    if (!orderNumberValue) {
      return json({
        error:
          "Order number is required"
      }, 400);
    }

    if (
      trackingUrl &&
      !/^https?:\/\//i.test(
        trackingUrl
      )
    ) {
      return json({
        error:
          "Tracking URL must start with http:// or https://"
      }, 400);
    }

    const result =
      await env.DB.prepare(`
        UPDATE orders
        SET
          courier_name = ?,
          tracking_number = ?,
          tracking_url = ?,
          updated_at = CURRENT_TIMESTAMP
        WHERE order_number = ?
      `).bind(
        courierName,
        trackingNumber,
        trackingUrl,
        orderNumberValue
      ).run();

    if (!result.meta?.changes) {
      return json({
        error:
          "Order not found"
      }, 404);
    }

    return json({
      ok: true,
      message:
        "Shipping details updated"
    });

  } catch (error) {
    return json({
      error:
        error?.message ||
        "Could not update shipping details"
    }, 400);
  }
}


/*
=========================================================
CUSTOMER MY ORDERS
=========================================================
*/

async function myOrders(request, env) {
  const url =
    new URL(request.url);

  const mobile =
    String(
      url.searchParams.get(
        "mobile"
      ) || ""
    ).trim();

  if (!/^\d{10}$/.test(mobile)) {
    return json({
      error:
        "Valid 10-digit mobile number required"
    }, 400);
  }

  try {
    const result =
      await env.DB.prepare(`
        SELECT
          order_number,
          mobile,
          amount_paise,
          payment_method,
          payment_status,
          order_status,
          items_json,
          courier_name,
          tracking_number,
          tracking_url,
          created_at,
          updated_at,
          shipped_at,
          delivered_at
        FROM orders
        WHERE mobile = ?
        ORDER BY id DESC
        LIMIT 50
      `).bind(mobile).all();

    const orders =
      (result.results || []).map(row => {

        let items = [];

        try {
          items =
            JSON.parse(
              row.items_json || "[]"
            );

          if (
            !Array.isArray(items)
          ) {
            items = [];
          }

        } catch {
          items = [];
        }

        return {
          order_number:
            row.order_number,

          mobile:
            row.mobile,

          amount_paise:
            Number(
              row.amount_paise || 0
            ),

          payment_method:
            row.payment_method || "",

          payment_status:
            row.payment_status || "",

          order_status:
            row.order_status || "",

          items,

          courier_name:
            row.courier_name || "",

          tracking_number:
            row.tracking_number || "",

          tracking_url:
            row.tracking_url || "",

          created_at:
            row.created_at || "",

          updated_at:
            row.updated_at || "",

          shipped_at:
            row.shipped_at || null,

          delivered_at:
            row.delivered_at || null
        };
      });

    return json({
      ok: true,
      orders
    });

  } catch (error) {
    return json({
      error:
        error?.message ||
        "Could not load orders"
    }, 500);
  }
}


/*
=========================================================
CREATE ORDER
=========================================================
*/

async function createOrder(request, env) {
  try {

    const body =
      await request.json();

    const amount =
      Number(body.amount);

    const customerName =
      String(
        body.customer_name || ""
      ).trim();

    const mobile =
      String(
        body.mobile || ""
      ).trim();

    const email =
      String(
        body.email || ""
      ).trim();

    const address =
      String(
        body.address || ""
      ).trim();

    const city =
      String(
        body.city || ""
      ).trim();

    const state =
      String(
        body.state || ""
      ).trim();

    const pincode =
      String(
        body.pincode || ""
      ).trim();

    const paymentMethod =
      String(
        body.payment_method ||
        "online"
      )
        .trim()
        .toLowerCase();

    const items =
      Array.isArray(body.items)
        ? body.items
        : [];

    if (
      !Number.isInteger(amount) ||
      amount <= 0 ||
      amount > 100000000
    ) {
      return json({
        error:
          "Invalid order amount"
      }, 400);
    }

    if (
      !customerName ||
      !/^\d{10}$/.test(mobile)
    ) {
      return json({
        error:
          "Valid customer name and 10-digit mobile are required"
      }, 400);
    }

    if (
      !address ||
      !city ||
      !state ||
      !pincode
    ) {
      return json({
        error:
          "Complete delivery address is required"
      }, 400);
    }

    if (
      ![
        "online",
        "cod"
      ].includes(paymentMethod)
    ) {
      return json({
        error:
          "Invalid payment method"
      }, 400);
    }

    if (!items.length) {
      return json({
        error:
          "Order must contain at least one item"
      }, 400);
    }

    const orderNo =
      orderNumber();

    let razorpayOrderId =
      null;

    if (
      paymentMethod === "online"
    ) {

      const rp =
        await razorpayRequest(
          env,
          "/orders",
          {
            method: "POST",

            body:
              JSON.stringify({
                amount:
                  amount * 100,

                currency:
                  "INR",

                receipt:
                  orderNo,

                notes: {
                  order_number:
                    orderNo
                }
              })
          }
        );

      razorpayOrderId =
        rp.id;
    }

    await env.DB
      .prepare(`
        INSERT INTO orders (
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
          items_json
        )
        VALUES (
          ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?
        )
      `)
      .bind(
        orderNo,
        razorpayOrderId,
        customerName,
        mobile,
        email,
        address,
        city,
        state,
        pincode,
        amount * 100,
        paymentMethod,

        paymentMethod === "cod"
          ? "pending"
          : "created",

        "new",

        JSON.stringify(items)
      )
      .run();

    return json({
      ok: true,

      order_number:
        orderNo,

      razorpay_order_id:
        razorpayOrderId,

      amount_paise:
        amount * 100,

      currency:
        "INR",

      payment_method:
        paymentMethod
    });

  } catch (error) {

    return json({
      error:
        error?.message ||
        "Could not create order"
    }, 500);
  }
}


/*
=========================================================
VERIFY PAYMENT
=========================================================
*/

async function verifyPayment(
  request,
  env
) {
  try {

    const body =
      await request.json();

    const orderNumberValue =
      String(
        body.order_number || ""
      ).trim();

    const razorpayOrderId =
      String(
        body.razorpay_order_id ||
        ""
      ).trim();

    const razorpayPaymentId =
      String(
        body.razorpay_payment_id ||
        ""
      ).trim();

    const razorpaySignature =
      String(
        body.razorpay_signature ||
        ""
      ).trim();

    if (
      !orderNumberValue ||
      !razorpayOrderId ||
      !razorpayPaymentId ||
      !razorpaySignature
    ) {
      return json({
        error:
          "Incomplete payment verification data"
      }, 400);
    }

    const order =
      await env.DB
        .prepare(`
          SELECT
            id,
            order_number,
            razorpay_order_id,
            payment_status
          FROM orders
          WHERE order_number = ?
          LIMIT 1
        `)
        .bind(
          orderNumberValue
        )
        .first();

    if (!order) {
      return json({
        error:
          "Order not found"
      }, 404);
    }

    if (
      order.razorpay_order_id !==
      razorpayOrderId
    ) {
      return json({
        error:
          "Razorpay order mismatch"
      }, 400);
    }

    const valid =
      await verifyRazorpaySignature(
        razorpayOrderId,
        razorpayPaymentId,
        razorpaySignature,
        env.RAZORPAY_KEY_SECRET
      );

    if (!valid) {
      return json({
        error:
          "Payment signature verification failed"
      }, 400);
    }

    await env.DB
      .prepare(`
        UPDATE orders
        SET
          razorpay_payment_id = ?,
          payment_status = 'paid',
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(
        razorpayPaymentId,
        order.id
      )
      .run();

    return json({
      ok: true,

      order_number:
        orderNumberValue,

      payment_status:
        "paid"
    });

  } catch (error) {

    return json({
      error:
        error?.message ||
        "Could not verify payment"
    }, 500);
  }
}


/*
=========================================================
WEBHOOK
=========================================================
*/

async function webhook(request, env) {
  try {

    const rawBody =
      await request.text();

    if (
      env.RAZORPAY_WEBHOOK_SECRET
    ) {

      const signature =
        request.headers.get(
          "x-razorpay-signature"
        ) || "";

      const key =
        await crypto.subtle.importKey(
          "raw",
          new TextEncoder().encode(
            env.RAZORPAY_WEBHOOK_SECRET
          ),
          {
            name: "HMAC",
            hash: "SHA-256"
          },
          false,
          ["sign"]
        );

      const sigBuffer =
        await crypto.subtle.sign(
          "HMAC",
          key,
          new TextEncoder().encode(
            rawBody
          )
        );

      const expected =
        [...new Uint8Array(
          sigBuffer
        )]
          .map(b =>
            b.toString(16)
             .padStart(2, "0")
          )
          .join("");

      if (
        expected !==
        signature.toLowerCase()
      ) {
        return json({
          error:
            "Invalid webhook signature"
        }, 400);
      }
    }

    let payload = {};

    try {
      payload =
        JSON.parse(rawBody);
    } catch {
      payload = {};
    }

    const event =
      String(
        payload.event || ""
      );

    if (
      event ===
        "payment.captured" ||
      event ===
        "payment.authorized"
    ) {

      const payment =
        payload?.payload
          ?.payment
          ?.entity;

      const razorpayOrderId =
        String(
          payment?.order_id || ""
        ).trim();

      const paymentId =
        String(
          payment?.id || ""
        ).trim();

      if (
        razorpayOrderId &&
        paymentId
      ) {

        await env.DB
          .prepare(`
            UPDATE orders
            SET
              razorpay_payment_id = ?,
              payment_status = 'paid',
              updated_at = CURRENT_TIMESTAMP
            WHERE razorpay_order_id = ?
          `)
          .bind(
            paymentId,
            razorpayOrderId
          )
          .run();
      }
    }

    return json({
      ok: true
    });

  } catch (error) {

    return json({
      error:
        error?.message ||
        "Webhook error"
    }, 500);
  }
}


/*
=========================================================
API ROUTER
=========================================================
*/

async function handleApi(
  request,
  env
) {

  const url =
    new URL(request.url);

  if (
    request.method ===
    "OPTIONS"
  ) {

    return new Response(
      null,
      {
        status: 204,
        headers:
          corsHeaders
      }
    );
  }


  if (
    url.pathname ===
      "/api/config" &&
    request.method ===
      "GET"
  ) {

    return json({
      ok: true,

      razorpay_key_id:
        env.RAZORPAY_KEY_ID ||
        ""
    });
  }


  if (
    url.pathname ===
      "/api/create-order" &&
    request.method ===
      "POST"
  ) {

    return createOrder(
      request,
      env
    );
  }


  if (
    url.pathname ===
      "/api/verify-payment" &&
    request.method ===
      "POST"
  ) {

    return verifyPayment(
      request,
      env
    );
  }


  if (
    url.pathname ===
      "/api/webhook" &&
    request.method ===
      "POST"
  ) {

    return webhook(
      request,
      env
    );
  }


  /*
  CUSTOMER MY ORDERS
  */

  if (
    url.pathname ===
      "/api/my-orders" &&
    request.method ===
      "GET"
  ) {

    return myOrders(
      request,
      env
    );
  }


  /*
  PUBLIC PRODUCTS
  */

  if (
    url.pathname ===
      "/api/products" &&
    request.method ===
      "GET"
  ) {

    return publicProducts(
      request,
      env
    );
  }


  /*
  ADMIN PRODUCTS
  */

  if (
    url.pathname ===
      "/api/admin/products" &&
    request.method ===
      "GET"
  ) {

    return adminProducts(
      request,
      env
    );
  }


  if (
    url.pathname ===
      "/api/admin/products" &&
    request.method ===
      "POST"
  ) {

    return createProduct(
      request,
      env
    );
  }


  if (
    url.pathname ===
      "/api/admin/products" &&
    request.method ===
      "PUT"
  ) {

    return updateProduct(
      request,
      env
    );
  }


  if (
    url.pathname ===
      "/api/admin/products" &&
    request.method ===
      "DELETE"
  ) {

    return deleteProduct(
      request,
      env
    );
  }


  /*
  ADMIN ORDERS
  */

  if (
    url.pathname ===
      "/api/admin/orders" &&
    request.method ===
      "GET"
  ) {

    return adminOrders(
      request,
      env
    );
  }


  /*
  ADMIN SHIPPING
  */

  if (
    url.pathname ===
      "/api/admin/shipping" &&
    request.method ===
      "POST"
  ) {

    return adminShipping(
      request,
      env
    );
  }


  /*
  ADMIN ORDER STATUS
  */

  if (
    url.pathname ===
      "/api/admin/order-status" &&
    request.method ===
      "POST"
  ) {

    return adminOrderStatus(
      request,
      env
    );
  }


  return json({
    error:
      "API endpoint not found"
  }, 404);
}


/*
=========================================================
CLOUDFLARE WORKER
=========================================================
*/

export default {

  async fetch(
    request,
    env,
    ctx
  ) {

    try {

      const url =
        new URL(request.url);

      if (
        url.pathname.startsWith(
          "/api/"
        )
      ) {

        return withCors(
          await handleApi(
            request,
            env
          )
        );
      }

      return env.ASSETS.fetch(
        request
      );

    } catch (error) {

      return json({
        error:
          error?.message ||
          "Internal server error"
      }, 500);
    }
  }
};
