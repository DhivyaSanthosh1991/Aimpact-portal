import { getStore } from "@netlify/blobs";
import { createApi } from "../lib/core.mjs";

const handle = createApi({
  store: getStore({ name: "aimpact", consistency: "strong" }),
  env: {
    OWNER_USER_ID: process.env.OWNER_USER_ID,
    OWNER_PASSWORD: process.env.OWNER_PASSWORD,
    SESSION_SECRET: process.env.SESSION_SECRET,
    TURNSTILE_SECRET: process.env.TURNSTILE_SECRET,
    OWNER_2FA_RESET: process.env.OWNER_2FA_RESET,
    RESEND_API_KEY: process.env.RESEND_API_KEY,
    RESEND_FROM_EMAIL: process.env.RESEND_FROM_EMAIL,
  },
});

export default async (req, context) => {
  const path = new URL(req.url).pathname.replace(/^\/api/, "");
  let body = null;
  if (req.method !== "GET" && req.method !== "HEAD") {
    const raw = await req.text();
    if (raw.length > 200_000) return Response.json({ error: "Request too large." }, { status: 413 });
    try { body = raw ? JSON.parse(raw) : null; } catch { return Response.json({ error: "Invalid JSON." }, { status: 400 }); }
  }
  const headers = Object.fromEntries(req.headers);
  const ip = req.headers.get("x-nf-client-connection-ip") || context?.ip || "";
  const { status, body: out, cookies, raw, contentType, filename } = await handle(req.method, path, body, { headers, ip });
  const res = raw !== undefined
    ? new Response(raw, { status, headers: { "cache-control": "no-store", "content-type": contentType, "content-disposition": `attachment; filename="${filename}"` } })
    : Response.json(out, { status, headers: { "cache-control": "no-store" } });
  for (const c of cookies || []) res.headers.append("set-cookie", c);
  return res;
};

export const config = { path: "/api/*" };
