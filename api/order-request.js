// api/order-request.js
import crypto from 'node:crypto';

const DEBUG = process.env.DEBUG === '1';

// ---- ENV ----
const SHOPIFY_SHOP        = process.env.SHOPIFY_SHOP;          // your-store.myshopify.com
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;   // shpat_...
const SHOPIFY_API_SECRET  = process.env.SHOPIFY_API_SECRET || ''; // App Proxy secret (leave blank if not using)
const SHOPIFY_API_VERSION = process.env.SHOPIFY_API_VERSION || '2023-10';

// For DIRECT mode (no App Proxy):
const ALLOW_ORIGIN      = process.env.ALLOW_ORIGIN || '';       // e.g. https://yourstore.com
const ALLOW_SHOP_DOMAIN = process.env.ALLOW_SHOP_DOMAIN || '';  // e.g. your-store.myshopify.com
const STORE_NOTIFY_EMAIL = process.env.STORE_NOTIFY_EMAIL || ''; // optional BCC

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

function passDirectGuards(req) {
  const origin = req.headers.origin || '';
  const shopHdr = req.headers['x-shop-domain'] || '';
  if (ALLOW_ORIGIN && origin !== ALLOW_ORIGIN) return false;
  if (ALLOW_SHOP_DOMAIN && shopHdr !== ALLOW_SHOP_DOMAIN) return false;
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
    if (ALLOW_ORIGIN) {
      res.setHeader('Access-Control-Allow-Origin', ALLOW_ORIGIN);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Shop-Domain');
      res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    }
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST, OPTIONS');
    return res.status(405).json({ message: 'Method Not Allowed' });
  }

  // Security gates
  if (isAppProxy(req)) {
    if (!validateAppProxySignature(req)) {
      return res.status(401).json({ message: 'Invalid app proxy signature' });
    }
  } else {
    if (!passDirectGuards(req)) {
      return res.status(401).json({ message: 'Unauthorized origin/shop' });
    }
    if (ALLOW_ORIGIN) {
      res.setHeader('Access-Control-Allow-Origin', ALLOW_ORIGIN);
      res.setHeader('Vary', 'Origin');
    }
  }

  // Parse JSON body (Vercel already parses when Content-Type: application/json)
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
    const draftPayload = {
      draft_order: {
        line_items,
        email: customer_context.email,
        customer: customerId ? { id: customerId } : undefined,
        note: noteLines.join('\n'),
        tags: ['Order Request', 'Pending Approval'],
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
    let invoiceSent = true;
    try {
      const invBody = {
        draft_order_invoice: {
          to: customer_context.email,
          bcc: STORE_NOTIFY_EMAIL || undefined,
          subject: `Order request ${draft.name}`,
          custom_message: `Hi ${customer_context.name},\n\nWe received your order request. Reference: ${draft.name}\nOur team will review and confirm next steps.\n\nThank you.`
        }
      };
      await admin(`/draft_orders/${draft.id}/send_invoice.json`, {
        method: 'POST',
        body: JSON.stringify(invBody)
      });
    } catch (e) {
      invoiceSent = false;
      console.warn('send_invoice failed:', e?.message || e);
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
      mode: isAppProxy(req) ? 'app_proxy' : 'direct'
    });
  } catch (e) {
    console.error('Handler error:', e?.message || e);
    if (DEBUG) {
      return res.status(500).json({ message: 'Server error', detail: String(e?.message || e) });
    }
    return res.status(500).json({ message: 'Server error' });
  }

}
