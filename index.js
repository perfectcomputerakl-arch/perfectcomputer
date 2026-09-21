const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json;charset=UTF-8"
    }
  });


const corsHeaders = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "Content-Type, Authorization"
};


function withCors(response) {

  const h = new Headers(response.headers);

  for (const [k, v] of Object.entries(corsHeaders)) {
    h.set(k, v);
  }

  return new Response(response.body, {
    status: response.status,
    headers: h
  });

}


function orderNumber() {

  const d = new Date();

  const stamp =
    d.toISOString()
      .replace(/\D/g, "")
      .slice(0, 14);

  const rnd =
    crypto.randomUUID()
      .slice(0, 6)
      .toUpperCase();

  return `PC-${stamp}-${rnd}`;

}


/* =========================================================
   RAZORPAY
   ========================================================= */

async function razorpayRequest(
  env,
  path,
  options = {}
) {

  const auth = btoa(
    `${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`
  );

  const res = await fetch(
    `https://api.razorpay.com/v1${path}`,
    {
      ...options,

      headers: {
        "Authorization": `Basic ${auth}`,
        "Content-Type": "application/json",
        ...(options.headers || {})
      }
    }
  );

  const data = await res.json();

  if (!res.ok) {

    throw new Error(
      data.error?.description ||
      "Razorpay API error"
    );

  }

  return data;

}


/* =========================================================
   VERIFY RAZORPAY SIGNATURE
   ========================================================= */

async function verifySignature(
  secret,
  orderId,
  paymentId,
  signature
) {

  const enc = new TextEncoder();

  const key =
    await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      {
        name: "HMAC",
        hash: "SHA-256"
      },
      false,
      ["sign"]
    );


  const sig =
    await crypto.subtle.sign(
      "HMAC",
      key,
      enc.encode(
        `${orderId}|${paymentId}`
      )
    );


  const hex =
    [...new Uint8Array(sig)]
      .map(
        b =>
          b.toString(16)
            .padStart(2, "0")
      )
      .join("");


  return hex === signature;

}


/* =========================================================
   ADMIN AUTHENTICATION
   ========================================================= */

function requireAdmin(request, env) {

  const auth =
    request.headers.get(
      "Authorization"
    ) || "";


  if (!auth.startsWith("Bearer ")) {
    return false;
  }


  const token =
    auth
      .slice(7)
      .trim();


  if (!env.ADMIN_TOKEN || !token) {
    return false;
  }


  return token === env.ADMIN_TOKEN;

}


/* =========================================================
   ADMIN — GET ORDERS
   ========================================================= */

async function adminOrders(
  request,
  env
) {

  if (!requireAdmin(request, env)) {

    return json({
      error: "Unauthorized"
    }, 401);

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


  return json({

    ok: true,

    orders:
      result.results || []

  });

}


/* =========================================================
   ADMIN — UPDATE ORDER STATUS
   ========================================================= */

async function adminOrderStatus(
  request,
  env
) {

  if (!requireAdmin(request, env)) {

    return json({
      error: "Unauthorized"
    }, 401);

  }


  let body;


  try {

    body =
      await request.json();

  } catch {

    return json({
      error: "Invalid JSON"
    }, 400);

  }


  const orderNumberValue =
    String(
      body.order_number || ""
    ).trim();


  const status =
    String(
      body.order_status || ""
    )
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
      error:
        "Invalid order number or status"
    }, 400);

  }


  let result;


  /* ================= SHIPPED ================= */

  if (status === "shipped") {

    result =
      await env.DB.prepare(`

        UPDATE orders

        SET

          order_status = ?,

          shipped_at =
            COALESCE(
              shipped_at,
              datetime('now')
            ),

          updated_at =
            datetime('now')

        WHERE order_number = ?

      `).bind(
        status,
        orderNumberValue
      ).run();

  }


  /* ================= DELIVERED ================= */

  else if (status === "delivered") {

    result =
      await env.DB.prepare(`

        UPDATE orders

        SET

          order_status = ?,

          delivered_at =
            COALESCE(
              delivered_at,
              datetime('now')
            ),

          updated_at =
            datetime('now')

        WHERE order_number = ?

      `).bind(
        status,
        orderNumberValue
      ).run();

  }


  /* ================= OTHER STATUS ================= */

  else {

    result =
      await env.DB.prepare(`

        UPDATE orders

        SET

          order_status = ?,

          updated_at =
            datetime('now')

        WHERE order_number = ?

      `).bind(
        status,
        orderNumberValue
      ).run();

  }


  if (!result.meta?.changes) {

    return json({
      error: "Order not found"
    }, 404);

  }


  return json({

    ok: true,

    order_number:
      orderNumberValue,

    order_status:
      status

  });

}


/* =========================================================
   ADMIN — UPDATE SHIPPING / TRACKING
   ========================================================= */

async function adminShipping(
  request,
  env
) {

  if (!requireAdmin(request, env)) {

    return json({
      error: "Unauthorized"
    }, 401);

  }


  let body;


  try {

    body =
      await request.json();

  } catch {

    return json({
      error: "Invalid JSON"
    }, 400);

  }


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
        "Order number required"
    }, 400);

  }


  /* Tracking URL validation */

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

        updated_at =
          datetime('now')

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

    order_number:
      orderNumberValue,

    courier_name:
      courierName,

    tracking_number:
      trackingNumber,

    tracking_url:
      trackingUrl

  });

}



/* =========================================================
   PRODUCT MANAGEMENT
   Additive only — does not modify existing orders.
   ========================================================= */

function productAdminData(body = {}) {
  const name = String(body.name || "").trim();
  const brand = String(body.brand || "").trim();
  const category = String(body.category || "").trim();
  const sku = String(body.sku || "").trim();
  const description = String(body.description || "").trim();
  const imageUrl = String(body.image_url || "").trim();
  const status = String(body.status || "active").trim().toLowerCase();

  const price = Number(body.price);
  const mrp = Number(body.mrp);
  const stockQty = Number(body.stock_qty);

  if (!name || !category) {
    throw new Error("Product name and category are required");
  }

  if (!Number.isFinite(price) || price < 0) {
    throw new Error("Invalid selling price");
  }

  if (!Number.isFinite(mrp) || mrp < 0) {
    throw new Error("Invalid MRP");
  }

  if (!Number.isInteger(stockQty) || stockQty < 0) {
    throw new Error("Invalid stock quantity");
  }

  if (!["active", "inactive"].includes(status)) {
    throw new Error("Invalid product status");
  }

  if (imageUrl && !/^https?:\/\//i.test(imageUrl)) {
    throw new Error("Image URL must start with http:// or https://");
  }

  return {
    name,
    brand,
    category,
    sku,
    description,
    image_url: imageUrl,
    price_paise: Math.round(price * 100),
    mrp_paise: Math.round(mrp * 100),
    stock_qty: stockQty,
    status
  };
}

async function adminProducts(request, env) {
  if (!requireAdmin(request, env)) {
    return json({ error: "Unauthorized" }, 401);
  }

  const result = await env.DB.prepare(`
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
    LIMIT 1000
  `).all();

  return json({
    ok: true,
    products: result.results || []
  });
}

async function createProduct(request, env) {
  if (!requireAdmin(request, env)) {
    return json({ error: "Unauthorized" }, 401);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  let p;
  try {
    p = productAdminData(body);
  } catch (e) {
    return json({ error: e.message }, 400);
  }

  const result = await env.DB.prepare(`
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
      status,
      created_at,
      updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
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
    product_id: result.meta?.last_row_id || null
  }, 201);
}

async function updateProduct(request, env) {
  if (!requireAdmin(request, env)) {
    return json({ error: "Unauthorized" }, 401);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  const id = Number(body.id);

  if (!Number.isInteger(id) || id <= 0) {
    return json({ error: "Valid product id required" }, 400);
  }

  let p;
  try {
    p = productAdminData(body);
  } catch (e) {
    return json({ error: e.message }, 400);
  }

  const result = await env.DB.prepare(`
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
      updated_at = datetime('now')
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
    return json({ error: "Product not found" }, 404);
  }

  return json({
    ok: true,
    product_id: id
  });
}

async function deleteProduct(request, env) {
  if (!requireAdmin(request, env)) {
    return json({ error: "Unauthorized" }, 401);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  const id = Number(body.id);

  if (!Number.isInteger(id) || id <= 0) {
    return json({ error: "Valid product id required" }, 400);
  }

  const result = await env.DB.prepare(`
    DELETE FROM products
    WHERE id = ?
  `).bind(id).run();

  if (!result.meta?.changes) {
    return json({ error: "Product not found" }, 404);
  }

  return json({
    ok: true,
    product_id: id
  });
}

async function publicProducts(request, env) {
  const result = await env.DB.prepare(`
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
      status
    FROM products
    WHERE status = 'active'
    ORDER BY id DESC
    LIMIT 1000
  `).all();

  return json({
    ok: true,
    products: result.results || []
  });
}


/* =========================================================
   CUSTOMER ACCOUNTS — additive upgrade
   ========================================================= */

async function ensureAccountTables(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS customer_accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      mobile TEXT NOT NULL UNIQUE,
      email TEXT DEFAULT '',
      address TEXT DEFAULT '',
      city TEXT DEFAULT '',
      state TEXT DEFAULT '',
      pincode TEXT DEFAULT '',
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS customer_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      account_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL
    )
  `).run();
}

function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
function hexToBytes(hex) {
  const out=new Uint8Array(hex.length/2);
  for(let i=0;i<out.length;i++) out[i]=parseInt(hex.slice(i*2,i*2+2),16);
  return out;
}
function randomHex(bytes=16) {
  const a=new Uint8Array(bytes); crypto.getRandomValues(a); return bytesToHex(a);
}
async function sha256Hex(text) {
  return bytesToHex(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text)));
}
async function hashPassword(password,saltHex) {
  const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveBits']);
  const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt:hexToBytes(saltHex),iterations:120000,hash:'SHA-256'},key,256);
  return bytesToHex(bits);
}
function accountMobile(v){ return String(v||'').replace(/\D/g,''); }
function validEmail(v){ return !v || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v)); }
async function accountFromRequest(request,env){
  const raw=request.headers.get('Authorization')||'';
  const token=raw.startsWith('Bearer ')?raw.slice(7).trim():'';
  if(!token)return null;
  const th=await sha256Hex(token);
  const row=await env.DB.prepare(`SELECT a.* FROM customer_sessions s JOIN customer_accounts a ON a.id=s.account_id WHERE s.token_hash=? AND s.expires_at > datetime('now')`).bind(th).first();
  return row||null;
}
function publicAccount(a){
  if(!a)return null;
  return {id:a.id,name:a.name,mobile:a.mobile,email:a.email||'',address:a.address||'',city:a.city||'',state:a.state||'',pincode:a.pincode||''};
}
async function createSession(accountId,env){
  const token=randomHex(32), hash=await sha256Hex(token);
  await env.DB.prepare(`INSERT INTO customer_sessions(account_id,token_hash,expires_at) VALUES(?,?,datetime('now','+30 days'))`).bind(accountId,hash).run();
  return token;
}
async function accountRegister(request,env){
  await ensureAccountTables(env);
  let b; try{b=await request.json()}catch{return json({error:'Invalid JSON'},400)}
  const name=String(b.name||'').trim(), mobile=accountMobile(b.mobile), email=String(b.email||'').trim();
  const address=String(b.address||'').trim(), city=String(b.city||'').trim(), state=String(b.state||'').trim(), pincode=String(b.pincode||'').trim();
  const password=String(b.password||'');
  if(!name || !/^\d{10}$/.test(mobile)) return json({error:'Valid name and 10-digit mobile are required'},400);
  if(password.length<8) return json({error:'Password must be at least 8 characters'},400);
  if(!validEmail(email)) return json({error:'Please enter a valid email'},400);
  const exists=await env.DB.prepare(`SELECT id FROM customer_accounts WHERE mobile=?`).bind(mobile).first();
  if(exists)return json({error:'An account already exists with this mobile number'},409);
  const salt=randomHex(16), ph=await hashPassword(password,salt);
  const r=await env.DB.prepare(`INSERT INTO customer_accounts(name,mobile,email,address,city,state,pincode,password_hash,password_salt,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'))`).bind(name,mobile,email,address,city,state,pincode,ph,salt).run();
  const id=r.meta?.last_row_id; const token=await createSession(id,env);
  return json({ok:true,token,account:publicAccount({id,name,mobile,email,address,city,state,pincode})},201);
}
async function accountLogin(request,env){
  await ensureAccountTables(env);
  let b; try{b=await request.json()}catch{return json({error:'Invalid JSON'},400)}
  const mobile=accountMobile(b.mobile), password=String(b.password||'');
  if(!/^\d{10}$/.test(mobile)||!password)return json({error:'Mobile and password are required'},400);
  const a=await env.DB.prepare(`SELECT * FROM customer_accounts WHERE mobile=?`).bind(mobile).first();
  if(!a)return json({error:'Account not found. Please sign up first.'},401);
  const ph=await hashPassword(password,a.password_salt);
  if(ph!==a.password_hash)return json({error:'Incorrect mobile or password'},401);
  const token=await createSession(a.id,env);
  return json({ok:true,token,account:publicAccount(a)});
}
async function accountMe(request,env){
  await ensureAccountTables(env); const a=await accountFromRequest(request,env);
  if(!a)return json({error:'Not logged in'},401); return json({ok:true,account:publicAccount(a)});
}
async function accountUpdate(request,env){
  await ensureAccountTables(env); const a=await accountFromRequest(request,env);
  if(!a)return json({error:'Not logged in'},401);
  let b; try{b=await request.json()}catch{return json({error:'Invalid JSON'},400)}
  const name=String(b.name||'').trim(), email=String(b.email||'').trim(), address=String(b.address||'').trim(), city=String(b.city||'').trim(), state=String(b.state||'').trim(), pincode=String(b.pincode||'').trim();
  if(!name)return json({error:'Name is required'},400); if(!validEmail(email))return json({error:'Invalid email'},400);
  await env.DB.prepare(`UPDATE customer_accounts SET name=?,email=?,address=?,city=?,state=?,pincode=?,updated_at=datetime('now') WHERE id=?`).bind(name,email,address,city,state,pincode,a.id).run();
  const fresh=await env.DB.prepare(`SELECT * FROM customer_accounts WHERE id=?`).bind(a.id).first(); return json({ok:true,account:publicAccount(fresh)});
}
async function accountLogout(request,env){
  await ensureAccountTables(env); const raw=request.headers.get('Authorization')||''; const token=raw.startsWith('Bearer ')?raw.slice(7).trim():'';
  if(token)await env.DB.prepare(`DELETE FROM customer_sessions WHERE token_hash=?`).bind(await sha256Hex(token)).run();
  return json({ok:true});
}
async function accountOrders(request,env){
  await ensureAccountTables(env); const a=await accountFromRequest(request,env);
  if(!a)return json({error:'Not logged in'},401);
  const r=await env.DB.prepare(`SELECT id,order_number,razorpay_order_id,razorpay_payment_id,customer_name,mobile,email,address,city,state,pincode,amount_paise,payment_method,payment_status,order_status,items_json,courier_name,tracking_number,tracking_url,shipped_at,delivered_at,created_at,updated_at FROM orders WHERE mobile=? ORDER BY id DESC LIMIT 500`).bind(a.mobile).all();
  return json({ok:true,orders:r.results||[]});
}
async function accountLinkInfo(request,env){
  await ensureAccountTables(env); const a=await accountFromRequest(request,env); if(!a)return json({error:'Not logged in'},401);
  const r=await env.DB.prepare(`SELECT COUNT(*) AS count FROM orders WHERE mobile=?`).bind(a.mobile).first(); return json({ok:true,linked_orders:Number(r?.count||0)});
}


/* =========================================================
   MAIN API HANDLER
   ========================================================= */

async function handleApi(
  request,
  env
) {

  const url =
    new URL(request.url);



  /* ================= CUSTOMER ACCOUNTS ================= */
  if(url.pathname === "/api/account/register" && request.method === "POST") return accountRegister(request,env);
  if(url.pathname === "/api/account/login" && request.method === "POST") return accountLogin(request,env);
  if(url.pathname === "/api/account/me" && request.method === "GET") return accountMe(request,env);
  if(url.pathname === "/api/account/update" && request.method === "POST") return accountUpdate(request,env);
  if(url.pathname === "/api/account/logout" && request.method === "POST") return accountLogout(request,env);
  if(url.pathname === "/api/account/orders" && request.method === "GET") return accountOrders(request,env);
  if(url.pathname === "/api/account/link-info" && request.method === "GET") return accountLinkInfo(request,env);

  /* ================= OPTIONS ================= */

  if (
    request.method === "OPTIONS"
  ) {

    return new Response(null, {
      status: 204,
      headers: corsHeaders
    });

  }


  /* =========================================================
     CONFIG
     ========================================================= */

  if (
    url.pathname === "/api/config" &&
    request.method === "GET"
  ) {

    return json({

      key_id:
        env.RAZORPAY_KEY_ID || ""

    });

  }


  /* =========================================================
     CREATE ORDER
     ========================================================= */

  if (
    url.pathname === "/api/create-order" &&
    request.method === "POST"
  ) {

    let body;


    try {

      body =
        await request.json();

    } catch {

      return json({
        error: "Invalid JSON"
      }, 400);

    }


    const amount =
      Number(body.amount);


    const c =
      body.customer || {};


    const items =
      Array.isArray(body.items)
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
        error:
          "Invalid order amount"
      }, 400);

    }


    if (
      !c.name ||
      !/^\d{10}$/.test(
        String(c.mobile)
      ) ||
      !c.address ||
      !c.city ||
      !c.state ||
      !/^\d{6}$/.test(
        String(c.pincode)
      )
    ) {

      return json({
        error:
          "Please provide valid customer details"
      }, 400);

    }


    if (!items.length) {

      return json({
        error:
          "Cart is empty"
      }, 400);

    }


    const orderNo =
      orderNumber();


    let razorOrderId =
      null;


    try {


      /* ================= RAZORPAY ORDER ================= */

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


        razorOrderId =
          rp.id;

      }


      /* ================= SAVE ORDER ================= */

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

        VALUES

        (
          ?,
          ?,

          ?,
          ?,
          ?,

          ?,
          ?,
          ?,
          ?,

          ?,

          ?,
          ?,
          ?,

          ?,

          datetime('now')
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

        order_number:
          orderNo,

        amount:
          amount * 100,

        currency:
          "INR",

        razorpay_order_id:
          razorOrderId

      });


    } catch (e) {

      return json({

        error:
          e.message ||
          "Could not create order"

      }, 500);

    }

  }


  /* =========================================================
     VERIFY PAYMENT
     ========================================================= */

  if (
    url.pathname === "/api/verify-payment" &&
    request.method === "POST"
  ) {

    let body;


    try {

      body =
        await request.json();

    } catch {

      return json({
        error:
          "Invalid JSON"
      }, 400);

    }


    if (
      !body.order_number ||
      !body.razorpay_order_id ||
      !body.razorpay_payment_id ||
      !body.razorpay_signature
    ) {

      return json({
        error:
          "Missing payment verification fields"
      }, 400);

    }


    const row =
      await env.DB.prepare(`

        SELECT *

        FROM orders

        WHERE order_number = ?

        AND razorpay_order_id = ?

      `).bind(

        body.order_number,

        body.razorpay_order_id

      ).first();


    if (!row) {

      return json({
        error:
          "Order not found"
      }, 404);

    }


    const valid =
      await verifySignature(

        env.RAZORPAY_KEY_SECRET,

        body.razorpay_order_id,

        body.razorpay_payment_id,

        body.razorpay_signature

      );


    if (!valid) {

      return json({
        error:
          "Invalid payment signature"
      }, 400);

    }


    await env.DB.prepare(`

      UPDATE orders

      SET

        razorpay_payment_id = ?,

        razorpay_signature = ?,

        payment_status = 'paid',

        order_status = 'confirmed',

        updated_at =
          datetime('now')

      WHERE order_number = ?

    `).bind(

      body.razorpay_payment_id,

      body.razorpay_signature,

      body.order_number

    ).run();


    return json({

      ok: true,

      order_number:
        body.order_number

    });

  }


  /* =========================================================
     RAZORPAY WEBHOOK
     ========================================================= */

  if (
    url.pathname === "/api/webhook" &&
    request.method === "POST"
  ) {

    const raw =
      await request.text();


    const signature =
      request.headers.get(
        "x-razorpay-signature"
      ) || "";


    if (
      !env.RAZORPAY_WEBHOOK_SECRET
    ) {

      return json({
        error:
          "Webhook secret not configured"
      }, 500);

    }


    const enc =
      new TextEncoder();


    const key =
      await crypto.subtle.importKey(

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


    const sig =
      await crypto.subtle.sign(

        "HMAC",

        key,

        enc.encode(raw)

      );


    const expected =
      [
        ...new Uint8Array(sig)
      ]
        .map(
          b =>
            b.toString(16)
              .padStart(2, "0")
        )
        .join("");


    if (
      expected !== signature
    ) {

      return json({
        error:
          "Invalid webhook signature"
      }, 400);

    }


    let event;


    try {

      event =
        JSON.parse(raw);

    } catch {

      return json({
        error:
          "Invalid webhook JSON"
      }, 400);

    }


    if (
      event.event ===
      "order.paid"
    ) {

      const order =
        event.payload
          ?.order
          ?.entity;


      const payment =
        event.payload
          ?.payment
          ?.entity;


      if (order?.receipt) {

        await env.DB.prepare(`

          UPDATE orders

          SET

            payment_status =
              'paid',

            order_status =
              'confirmed',

            razorpay_payment_id =
              COALESCE(
                ?,
                razorpay_payment_id
              ),

            updated_at =
              datetime('now')

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
     PRODUCTS — PUBLIC LIST
     ========================================================= */

  if (
    url.pathname === "/api/products" &&
    request.method === "GET"
  ) {
    return publicProducts(request, env);
  }


  /* =========================================================
     ADMIN — PRODUCTS
     ========================================================= */

  if (
    url.pathname === "/api/admin/products" &&
    request.method === "GET"
  ) {
    return adminProducts(request, env);
  }

  if (
    url.pathname === "/api/admin/products" &&
    request.method === "POST"
  ) {
    return createProduct(request, env);
  }

  if (
    url.pathname === "/api/admin/products" &&
    request.method === "PUT"
  ) {
    return updateProduct(request, env);
  }

  if (
    url.pathname === "/api/admin/products" &&
    request.method === "DELETE"
  ) {
    return deleteProduct(request, env);
  }


  /* =========================================================
     ADMIN — ORDERS
     ========================================================= */

  if (
    url.pathname ===
      "/api/admin/orders" &&
    request.method === "GET"
  ) {

    return adminOrders(
      request,
      env
    );

  }


  /* =========================================================
     ADMIN — SHIPPING
     ========================================================= */

  if (
    url.pathname ===
      "/api/admin/shipping" &&
    request.method === "POST"
  ) {

    return adminShipping(
      request,
      env
    );

  }


  /* =========================================================
     ADMIN — ORDER STATUS
     ========================================================= */

  if (
    url.pathname ===
      "/api/admin/order-status" &&
    request.method === "POST"
  ) {

    return adminOrderStatus(
      request,
      env
    );

  }


  return json({
    error: "Not found"
  }, 404);

}


/* =========================================================
   CLOUDFLARE WORKER
   ========================================================= */

export default {

  async fetch(
    request,
    env
  ) {

    const url =
      new URL(request.url);


    if (
      url.pathname.startsWith(
        "/api/"
      )
    ) {

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


    return env.ASSETS.fetch(
      request
    );

  }

};
