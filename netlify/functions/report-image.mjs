import { getStore } from "@netlify/blobs";

const STORE_NAME = "vant-report-images";

export default async (request, context) => {
  const id = context.params?.id || new URL(request.url).pathname.split("/").pop();
  if (request.method !== "GET" || !/^[0-9a-f-]{36}$/i.test(id || "")) {
    return new Response("Not found", { status: 404 });
  }

  const store = getStore(STORE_NAME);
  const key = `reports/${id}.jpg`;
  const meta = await store.getMetadata(key);
  if (!meta) return new Response("Not found", { status: 404 });

  const expiresAt = Number(meta.metadata?.expiresAt || 0);
  if (!expiresAt || expiresAt <= Date.now()) {
    await store.delete(key);
    return new Response("Expired", { status: 410 });
  }

  const blob = await store.get(key, { type: "blob", consistency: "strong" });
  if (!blob) return new Response("Not found", { status: 404 });

  return new Response(blob, {
    status: 200,
    headers: {
      "Content-Type": "image/jpeg",
      "Cache-Control": "public, max-age=300",
      "X-Content-Type-Options": "nosniff",
    },
  });
};

export const config = { path: "/report-image/:id" };
