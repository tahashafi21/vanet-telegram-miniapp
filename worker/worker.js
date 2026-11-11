/**
 * Vant Study Report sharing backend
 * Cloudflare Worker + R2
 *
 * Required Worker bindings/secrets:
 *   BOT_TOKEN              Secret: Telegram bot token
 *   ALLOWED_ORIGIN         Variable: exact GitHub Pages origin
 *   PUBLIC_R2_BASE_URL     Variable: public HTTPS base URL for the R2 bucket
 *   REPORTS                R2 bucket binding
 */
const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
const MAX_AUTH_AGE_SECONDS = 24 * 60 * 60;

function corsHeaders(origin, env) {
  const allowed = env.ALLOWED_ORIGIN || "";
  const headers = {
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "POST, OPTIONS, GET",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  };
  if (origin && origin === allowed) headers["Access-Control-Allow-Origin"] = origin;
  return headers;
}

function json(data, status, headers) {
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
  const entries = [...params.entries()].sort(([a], [b]) => a.localeCompare(b));
  const dataCheckString = entries.map(([k, v]) => `${k}=${v}`).join("\n");
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode("WebAppData"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const secret = await crypto.subtle.sign("HMAC", keyMaterial, enc.encode(botToken));
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

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const headers = corsHeaders(origin, env);
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      if (origin !== env.ALLOWED_ORIGIN) return new Response(null, { status: 403 });
      return new Response(null, { status: 204, headers });
    }

    if (url.pathname === "/health" && request.method === "GET") {
      return json({ ok: true, service: "vant-report-share" }, 200, headers);
    }

    if (url.pathname !== "/prepare" || request.method !== "POST") {
      return json({ ok: false, error: "Not found" }, 404, headers);
    }
    if (origin !== env.ALLOWED_ORIGIN) {
      return json({ ok: false, error: "Origin not allowed" }, 403, headers);
    }
    if (!env.BOT_TOKEN || !env.REPORTS || !env.PUBLIC_R2_BASE_URL) {
      return json({ ok: false, error: "Backend is not configured" }, 503, headers);
    }

    let form;
    try { form = await request.formData(); }
    catch { return json({ ok: false, error: "Invalid multipart form" }, 400, headers); }

    const user = await verifyTelegramInitData(String(form.get("initData") || ""), env.BOT_TOKEN);
    if (!user) return json({ ok: false, error: "Telegram authentication failed. Reopen the Mini App." }, 401, headers);

    const image = form.get("image");
    if (!(image instanceof File) || image.type !== "image/jpeg" || image.size < 100 || image.size > MAX_IMAGE_BYTES) {
      return json({ ok: false, error: "JPEG must be between 100 bytes and 5 MB" }, 400, headers);
    }

    const id = crypto.randomUUID();
    const key = `reports/${id}.jpg`;
    const publicBase = env.PUBLIC_R2_BASE_URL.replace(/\/+$/, "");
    const photoUrl = `${publicBase}/${key}`;

    try {
      await env.REPORTS.put(key, image.stream(), {
        httpMetadata: { contentType: "image/jpeg", cacheControl: "public, max-age=86400" },
        customMetadata: { owner: String(user.id), createdAt: new Date().toISOString() },
      });

      const caption = String(form.get("caption") || "گزارش مطالعه روزانه | گروه آموزشی وانت").slice(0, 900);
      const tgResponse = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/savePreparedInlineMessage`, {
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
        await env.REPORTS.delete(key);
        return json({ ok: false, error: tgData.description || "Telegram could not prepare the image" }, 502, headers);
      }

      return json({
        ok: true,
        prepared_message_id: tgData.result.id,
        expires_at: tgData.result.expiration_date || null,
      }, 200, headers);
    } catch (error) {
      try { await env.REPORTS.delete(key); } catch {}
      return json({ ok: false, error: "Could not prepare report image" }, 502, headers);
    }
  },
};
