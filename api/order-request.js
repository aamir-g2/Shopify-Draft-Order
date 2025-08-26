// api/order-request.js
import crypto from 'node:crypto';

const DEBUG = process.env.DEBUG === '1';

// ---- ENV ----
const SHOPIFY_SHOP        = process.env.SHOPIFY_SHOP;          // e.g. g2-thelab.myshopify.com
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;   // shpat_...
const SHOPIFY_API_SECRET  = process.env.SHOPIFY_API_SECRET || ''; // App Proxy secret (if using)
const SHOPIFY_API_VERSION = process.env.SHOPIFY_API_VERSION || '2025-01';

// For DIRECT mode (no App Proxy):
const ALLOW_ORIGIN_RAW      = process.env.ALLOW_ORIGIN || '';      // comma-separated allowed origins
const ALLOW_SHOP_DOMAIN_RAW = process.env.ALLOW_SHOP_DOMAIN || ''; // comma-separated shop domains
const STORE_NOTIFY_EMAIL    = process.env.STORE_NOTIFY_EMAIL || ''; // optional BCC

function parseList(s) {
  return String(s || '')
    .split(',')
    .map(v => v.trim().replace(/\/$/, '').toLowerCase())
    .filter(Boolean);
}
const ALLOW_ORIGINS = parseList(ALLOW_ORIGIN_RAW);
const ALLOW_SHOPS   = parseList(ALLOW_SHOP_DOMAIN_RAW);

function isAppProxy(req) {
  return typeof req.query?.signature === 'string';
}

// Validate App Proxy signature (HMAC SHA256 over sorted query, excluding `signature`)
function validateAppProxySignature(req) {
  if (!SHOPIFY_API_SECRET) return false;
  const { signature, ...rest } = req.query || {};
  if (!signature) return false;

  const pairs = Object.keys(rest)
    .sort()
    .map((k) => {
      const v = Array.isArray(rest[k]) ? rest[k][0] : rest[k];
      return `${k}=${v}`;
    });

  const message = pairs.join('');
  const digest = crypto.createHmac('sha256', SHOPIFY_API_SECRET).update(message).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(digest, 'hex'), Buffer.from(signature, 'hex'));
  } catch {
    return false;
  }
}

function passDirectGuards(req, res) {
  const origin  = String(req.headers.origin || '').replace(/\/$/, '').toLowerCase();
  const shopHdr = String(req.headers['x-shop-domain'] || '').toLowerCase();

  const okOrigin = !ALLOW_ORIGINS.length || ALLOW_ORIGINS.includes(origin);
  const okShop   = !ALLOW_SHOPS.length   || ALLOW_SHOPS.includes(shopHdr);
  if (!okOrigin || !okShop) return false;

  // Reflect origin for CORS if we’re allowing it
  if (origin && ALLOW_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  return true;
}

function gidToNumericId(idOrGid) {
  if (typeof idOrGid === 'number') return idOrGid;
  const s = String(idOrGid || '');
  return s.startsWith('gid://') ? Number(s.split('/').pop() || '0') : Number(s);
}

async function admin(path, init = {}) {
  const res = await fetch(`https://${SHOPIFY_SHOP}/admin/api/${SHOPIFY_API_VERSION}${path}`, {
    ...init,
    headers: {
      'X-Shopify-Access-Token': SHOPIFY_ADMIN_TOKEN,
      'Content-Type': 'application/json',
      ...(init.headers || {})
    }
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Admin API ${path} failed: ${res.status} ${res.statusText} - ${text}`);
  }
  return res.json();
}

export default async function handler(req, res) {
  // CORS preflight for DIRECT mode
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Shop-Domain');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    // We reflect the actual Origin in passDirectGuards; here we can be permissive
    if (ALLOW_ORIGINS.length) {
      const origin = String(req.headers.origin || '').replace(/\/$/, '').toLowerCase();
      if (ALLOW_ORIGINS.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
      }
    }
    return res.status(204).end();
  }

  // ✅ DEBUG GET placed BEFORE 405 so it actually runs
  if (DEBUG && req.method === 'GET') {
    return res.status(200).json({
      shop: process.env.SHOPIFY_SHOP,
      apiVersion: process.env.SHOPIFY_API_VERSION,
      hasToken: !!process.env.SHOPIFY_ADMIN_TOKEN,
      tokenLen: (process.env.SHOPIFY_ADMIN_TOKEN || '').length,
      allowOrigins: ALLOW_ORIGINS,
      allowShops: ALLOW_SHOPS
    });
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', DEBUG ? 'POST, GET, OPTIONS' : 'POST, OPTIONS');
    return res.status(405).json({ message: 'Method Not Allowed' });
  }

  // Security gates
  if (isAppProxy(req)) {
    if (!validateAppProxySignature(req)) {
      return res.status(401).json({ message: 'Invalid app proxy signature' });
    }
  } else {
    if (!passDirectGuards(req, res)) {
      if (DEBUG) {
        const origin = String(req.headers.origin || '');
        const shopHdr = String(req.headers['x-shop-domain'] || '');
        return res.status(401).json({
          message: 'Unauthorized origin/shop',
          got: { origin, shop: shopHdr },
          expect: { origins: ALLOW_ORIGINS, shops: ALLOW_SHOPS }
        });
      }
      return res.status(401).json({ message: 'Unauthorized origin/shop' });
    }
  }

  // Parse JSON body
  const input = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || null);
  if (!input) return res.status(400).json({ message: 'Invalid JSON body' });

  const { items, customer_context, notes, totals, source_url } = input;
  if (!Array.isArray(items) || !items.length) return res.status(400).json({ message: 'No items' });
  if (!customer_context?.email || !customer_context?.name) {
    return res.status(400).json({ message: 'Name and email are required' });
  }

  try {
    // Optional: find customer by email
    let customerId;
    try {
      const search = await admin(`/customers/search.json?query=${encodeURIComponent(`email:${customer_context.email}`)}`);
      if (Array.isArray(search?.customers) && search.customers.length) {
        customerId = search.customers[0].id;
      }
    } catch (e) {
      console.warn('Customer search failed:', e?.message || e);
    }

    // Line items
    const line_items = items
      .map((it) => ({
        variant_id: gidToNumericId(it.variant_id),
        quantity: Number(it.quantity || 0)
      }))
      .filter((li) => li.variant_id && li.quantity > 0);

    const noteLines = [
      'Order request via storefront',
      `From: ${customer_context.name} <${customer_context.email}>`,
      customer_context.company ? `Company: ${customer_context.company}` : '',
      customer_context.phone ? `Phone: ${customer_context.phone}` : '',
      notes ? `Notes: ${notes}` : '',
      source_url ? `Source: ${source_url}` : '',
      totals?.subtotal_ex_vat ? `Subtotal (ex VAT, indicative): ${totals.subtotal_ex_vat}` : ''
    ].filter(Boolean);

    // Create Draft Order
    const TAGS = ['Order Request', 'Pending Approval'];

    const draftPayload = {
      draft_order: {
        line_items,
        email: customer_context.email,
        customer: customerId ? { id: customerId } : undefined,
        note: noteLines.join('\n'),
        tags: TAGS.join(', '),                  // ← string, not array
        use_customer_default_address: true
      }
    };


    const draftRes = await admin('/draft_orders.json', {
      method: 'POST',
      body: JSON.stringify(draftPayload)
    });
    const draft = draftRes?.draft_order;
    if (!draft?.id) return res.status(502).json({ message: 'Failed to create draft order', detail: draftRes });

    // Send invoice (Shopify emails the customer; optional BCC to store)
    // Strategy: try minimal payload first (highest compatibility). If it fails, retry with subject/custom_message.
    let invoiceSent = false;
    let invoiceError = null;

    async function trySend(body) {
      await admin(`/draft_orders/${draft.id}/send_invoice.json`, {
        method: 'POST',
        body: JSON.stringify(body)
      });
    }

    try {
      // 1) Minimal request
      await trySend({
        draft_order_invoice: {
          to: customer_context.email,
          bcc: STORE_NOTIFY_EMAIL || undefined
        }
      });
      invoiceSent = true;
    } catch (e1) {
      invoiceError = e1?.message || String(e1);
      console.warn('send_invoice minimal failed:', invoiceError);
      // 2) Retry with subject/custom message
      try {
        await trySend({
          draft_order_invoice: {
            to: customer_context.email,
            bcc: STORE_NOTIFY_EMAIL || undefined,
            subject: `Order request ${draft.name}`,
            custom_message: `Hi ${customer_context.name},\n\nWe received your order request. Reference: ${draft.name}\nOur team will review and confirm next steps.\n\nThank you.`
          }
        });
        invoiceSent = true;
        invoiceError = null;
      } catch (e2) {
        invoiceError = e2?.message || String(e2);
        console.warn('send_invoice with subject/custom_message failed:', invoiceError);
      }
    }


    return res.status(200).json({
      ok: true,
      draft_order: {
        id: draft.id,
        name: draft.name,
        admin_url: `https://${SHOPIFY_SHOP}/admin/draft_orders/${draft.id}`,
        invoice_url: draft.invoice_url
      },
      invoice_sent: invoiceSent,
      ...(DEBUG && !invoiceSent ? { invoice_error: invoiceError } : {}),
      mode: isAppProxy(req) ? 'app_proxy' : 'direct'
    });
  } catch (e) {
    console.error('Handler error:', e?.message || e);
    if (DEBUG) return res.status(500).json({ message: 'Server error', detail: String(e?.message || e) });
    return res.status(500).json({ message: 'Server error' });
  }
}
