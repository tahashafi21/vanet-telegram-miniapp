import { getStore } from "@netlify/blobs";

const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
const MAX_AUTH_AGE_SECONDS = 24 * 60 * 60;
const DEFAULT_ALLOWED_ORIGIN = "https://tahashafi21.github.io";
const STORE_NAME = "vant-report-images";

function corsHeaders(origin) {
  const allowed = process.env.ALLOWED_ORIGIN || DEFAULT_ALLOWED_ORIGIN;
  const headers = {
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  };
  if (origin && origin === allowed) headers["Access-Control-Allow-Origin"] = origin;
  return headers;
}

function json(data, status, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
  });
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

async function verifyTelegramInitData(initData, botToken) {
  if (!initData || !botToken) return null;
  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  if (!hash || !/^[a-f0-9]{64}$/i.test(hash)) return null;
  params.delete("hash");
  params.delete("signature");
  const entries = [...params.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
  const dataCheckString = entries.map(([k, v]) => `${k}=${v}`).join("\n");
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(botToken), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const secret = await crypto.subtle.sign("HMAC", keyMaterial, enc.encode("WebAppData"));
  const hmacKey = await crypto.subtle.importKey(
    "raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const digest = await crypto.subtle.sign("HMAC", hmacKey, enc.encode(dataCheckString));
  const calculated = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
  if (!safeEqual(calculated.toLowerCase(), hash.toLowerCase())) return null;

  const authDate = Number(params.get("auth_date") || 0);
  const now = Math.floor(Date.now() / 1000);
  if (!authDate || authDate > now + 60 || now - authDate > MAX_AUTH_AGE_SECONDS) return null;
  let user;
  try { user = JSON.parse(params.get("user") || "null"); } catch { return null; }
  if (!user || !Number.isSafeInteger(Number(user.id))) return null;
  return user;
}

async function cleanupExpired(store) {
  const { blobs } = await store.list({ prefix: "reports/" });
  const now = Date.now();
  for (const item of blobs) {
    try {
      const meta = await store.getMetadata(item.key);
      if (!meta || Number(meta.metadata?.expiresAt || 0) <= now) await store.delete(item.key);
    } catch {}
  }
}

export default async (request) => {
  const origin = request.headers.get("Origin") || "";
  const allowed = process.env.ALLOWED_ORIGIN || DEFAULT_ALLOWED_ORIGIN;
  const headers = corsHeaders(origin);

  if (request.method === "OPTIONS") {
    if (origin !== allowed) return new Response(null, { status: 403 });
    return new Response(null, { status: 204, headers });
  }
  if (request.method !== "POST") return json({ ok: false, error: "Method not allowed" }, 405, headers);
  if (origin !== allowed) return json({ ok: false, error: "Origin not allowed" }, 403, headers);

  const botToken = process.env.BOT_TOKEN;
  if (!botToken) return json({ ok: false, error: "BOT_TOKEN is not configured" }, 503, headers);

  let form;
  try { form = await request.formData(); }
  catch { return json({ ok: false, error: "Invalid multipart form" }, 400, headers); }

  const user = await verifyTelegramInitData(String(form.get("initData") || ""), botToken);
  if (!user) return json({ ok: false, error: "Telegram authentication failed. Reopen the Mini App." }, 401, headers);

  const image = form.get("image");
  if (!(image instanceof File) || image.type !== "image/jpeg" || image.size < 100 || image.size > MAX_IMAGE_BYTES) {
    return json({ ok: false, error: "JPEG must be between 100 bytes and 5 MB" }, 400, headers);
  }

  const store = getStore(STORE_NAME);
  const id = crypto.randomUUID();
  const key = `reports/${id}.jpg`;
  const expiresAt = Date.now() + 24 * 60 * 60 * 1000;
  const photoUrl = `${new URL(request.url).origin}/report-image/${id}`;

  try {
    await cleanupExpired(store);
    await store.set(key, await image.arrayBuffer(), {
      metadata: {
        owner: String(user.id),
        createdAt: new Date().toISOString(),
        expiresAt: String(expiresAt),
      },
    });

    const caption = String(form.get("caption") || "گزارش مطالعه روزانه | گروه آموزشی وانت").slice(0, 900);
    const tgResponse = await fetch(`https://api.telegram.org/bot${botToken}/savePreparedInlineMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        user_id: Number(user.id),
        result: {
          type: "photo",
          id,
          photo_url: photoUrl,
          thumbnail_url: photoUrl,
          title: "گزارش مطالعه وانت",
          description: "گزارش روزانه مطالعه",
          caption,
        },
        allow_user_chats: true,
        allow_group_chats: true,
        allow_channel_chats: true,
      }),
    });
    const tgData = await tgResponse.json();
    if (!tgResponse.ok || !tgData.ok || !tgData.result?.id) {
      await store.delete(key);
      return json({ ok: false, error: tgData.description || "Telegram could not prepare the image" }, 502, headers);
    }

    return json({
      ok: true,
      prepared_message_id: tgData.result.id,
      expires_at: tgData.result.expiration_date || null,
    }, 200, headers);
  } catch (error) {
    try { await store.delete(key); } catch {}
    return json({ ok: false, error: "Could not prepare report image" }, 502, headers);
  }
};

export const config = { path: "/api/prepare-report" };
