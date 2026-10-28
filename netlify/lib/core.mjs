// Request handling for the AImpact portal API. Pure logic: no Netlify imports,
// so it can be tested with an in-memory store (see test/core.test.mjs).
import { createHash, createHmac, randomBytes, randomInt, scryptSync, timingSafeEqual } from "node:crypto";

export const COLLECTIONS = ["providers", "consultants", "briefs"];
export const NOTICE_VERSION = "1.1";
// Contact details are not sent to the console with the lists. Staff fetch them one record at a
// time (logged), and staff can never overwrite them or the consent evidence.
export const PII_FIELDS = ["contactName", "designation", "contactEmail", "phone", "ref1"];
const PROTECTED_FIELDS = [...PII_FIELDS, "refHash", "consentAt", "noticeVersion", "submittedAt"];
const SESSION_HOURS = 8;
const TICKET_MINUTES = 5;
const MIN_FILL_MS = 4000;
const USER_RE = /^[a-z0-9._-]{3,32}$/;
const MAX_FIELD = 4000;
const MAX_RECORD_BYTES = 40_000;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ID_RE = /^[a-z0-9]{6,40}$/i;

const text = (v) => (typeof v === "string" ? v.trim().slice(0, MAX_FIELD) : "");
const newId = () => Date.now().toString(36) + randomBytes(4).toString("hex");

// ---- what each public form may send; everything else is dropped ----
const SPECS = {
  providers: {
    fields: ["contactName", "designation", "contactEmail", "phone", "name", "category", "sector", "description", "demoLink", "ref1", "smeApproach", "smeTimeline"],
    required: ["contactName", "contactEmail", "phone", "name", "description", "smeApproach"],
    build: (c, now) => ({
      ...c,
      capabilities: [],
      track: "Established",
      hasDemo: !!c.demoLink,
      status: "Pending",
      submittedAt: now,
      scores: {},
      totalScore: 0,
      tier: "",
    }),
  },
  consultants: {
    fields: ["name", "track", "sector", "portfolio", "contactEmail", "phone", "conflict"],
    required: ["name", "contactEmail", "phone", "portfolio"],
    build: (c, now, raw) => ({
      ...c,
      availability: Math.min(31, Math.max(0, Number(raw.availability) || 0)),
      status: "Pending",
      submittedAt: now,
      scores: {},
      totalScore: 0,
      tier: "",
    }),
  },
  briefs: {
    fields: ["orgName", "orgType", "sector", "problemStatement", "desiredOutcome", "contactEmail", "phone"],
    required: ["orgName", "problemStatement", "contactEmail", "phone"],
    build: (c, now) => ({
      ...c,
      stage: "Discovery",
      submittedAt: now,
      scoping: { problemDefinition: "", successMetrics: "", dataAvailability: "", budgetRange: "" },
      shortlist: [],
      proposals: {},
      selectedProviderId: null,
      selectedProviderName: null,
      selectionRationale: "",
      milestones: [],
      deliveryNotes: "",
      impact: { productivityGain: "", costSavings: "", adoptionNotes: "", rating: 0 },
      outcomeStatus: null,
      completedAt: null,
    }),
  },
};

function sanitiseSubmission(collection, raw) {
  const spec = SPECS[collection];
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { error: "Invalid submission." };
  const clean = {};
  for (const f of spec.fields) clean[f] = text(raw[f]);
  const missing = spec.required.filter((f) => !clean[f]);
  if (missing.length) return { error: `Missing required fields: ${missing.join(", ")}` };
  if (!EMAIL_RE.test(clean.contactEmail)) return { error: "Please enter a valid email address." };
  const built = spec.build(clean, new Date().toISOString(), raw);
  if (collection === "providers") {
    built.capabilities = Array.isArray(raw.capabilities)
      ? raw.capabilities.filter((c) => typeof c === "string").slice(0, 20).map((c) => c.slice(0, 200))
      : [];
  }
  return { record: { id: newId(), ...built } };
}

// ---- what the public may see ----
const publicProvider = (p) =>
  p.status === "Verified" || p.status === "Conditional"
    ? { id: p.id, name: p.name, category: p.category, sector: p.sector, description: p.description, capabilities: p.capabilities || [], status: p.status }
    : { id: p.id, status: p.status };
const publicConsultant = (c) => ({ id: c.id, status: c.status });
const publicBrief = (b) => ({
  id: b.id, stage: b.stage, outcomeStatus: b.outcomeStatus,
  selectedProviderId: b.selectedProviderId, impact: { rating: b.impact?.rating || 0 },
});

// ---------------------------------------------------------------
// Passwords, sessions, helpers
// ---------------------------------------------------------------
const digest = (s) => createHash("sha256").update(String(s)).digest();
const safeEqual = (a, b) => timingSafeEqual(digest(a), digest(b));
const b64 = (buf) => Buffer.from(buf).toString("base64url");

// ---------------------------------------------------------------
// Reference codes: shown once to the person who submits, needed (with their email) to check status
// ---------------------------------------------------------------
const REF_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"; // no 0/O/1/I/L: easy to read out loud
const REF_LEN = 10;
const refHash = (code) => createHash("sha256").update(`aimpact-ref|${code}`).digest("hex");
function newRefCode() {
  let c = "";
  for (let i = 0; i < REF_LEN; i++) c += REF_ALPHABET[randomInt(REF_ALPHABET.length)];
  return c;
}
export const formatRef = (c) => `AIM-${c.slice(0, 5)}-${c.slice(5)}`;
export function normaliseRef(input) {
  let s = String(input || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (s.startsWith("AIM") && s.length === REF_LEN + 3) s = s.slice(3);
  if (s.length !== REF_LEN) return "";
  for (const ch of s) if (!REF_ALPHABET.includes(ch)) return "";
  return s;
}

// ---------------------------------------------------------------
// Authenticator-app codes (RFC 6238: 6 digits, 30 seconds, SHA-1)
// ---------------------------------------------------------------
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export function base32Encode(buf) {
  let bits = 0, value = 0, out = "";
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
function base32Decode(str) {
  let bits = 0, value = 0; const out = [];
  for (const ch of String(str).toUpperCase().replace(/=+$/, "")) {
    const i = B32.indexOf(ch);
    if (i < 0) continue;
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
export function totpCode(secret, step) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const h = createHmac("sha1", base32Decode(secret)).update(msg).digest();
  const o = h[19] & 15;
  const n = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1_000_000).padStart(6, "0");
}
// Returns the matching 30-second step (never one already used), or null.
export function checkTotp(secret, code, lastStep, nowMs) {
  const c = String(code || "").replace(/\s+/g, "");
  if (!/^\d{6}$/.test(c)) return null;
  const now = Math.floor(nowMs / 30_000);
  let hit = null;
  for (const s of [now - 1, now, now + 1]) {
    if (s > (lastStep || 0) && safeEqual(totpCode(secret, s), c)) hit = hit === null ? s : Math.max(hit, s);
  }
  return hit;
}

// ---------------------------------------------------------------
// Exports and backups
// ---------------------------------------------------------------
async function readCollection(store, collection) {
  const { blobs } = await store.list({ prefix: `${collection}/` });
  const out = [];
  for (let i = 0; i < blobs.length; i += 25) {
    const chunk = await Promise.all(blobs.slice(i, i + 25).map((b) => store.get(b.key, { type: "json" })));
    out.push(...chunk.filter(Boolean));
  }
  return out.sort((a, b) => String(a.submittedAt).localeCompare(String(b.submittedAt)));
}

export async function snapshot(store, nowMs = Date.now()) {
  const [providers, consultants, briefs] = await Promise.all(COLLECTIONS.map((c) => readCollection(store, c)));
  return { takenAt: new Date(nowMs).toISOString(), noticeVersion: NOTICE_VERSION, providers, consultants, briefs };
}

// Writes today's snapshot to a separate store and keeps the most recent `keep` days.
export async function runBackup({ store, backupStore, nowMs = Date.now(), keep = 14 }) {
  const snap = await snapshot(store, nowMs);
  const day = snap.takenAt.slice(0, 10);
  await backupStore.setJSON(`daily/${day}.json`, snap);
  const { blobs } = await backupStore.list({ prefix: "daily/" });
  const keys = blobs.map((b) => b.key).sort();
  const drop = keys.slice(0, Math.max(0, keys.length - keep));
  for (const k of drop) await backupStore.delete(k);
  return { day, counts: { providers: snap.providers.length, consultants: snap.consultants.length, briefs: snap.briefs.length }, pruned: drop.length };
}

// Puts a snapshot back (used by scripts/restore.mjs). Existing records with the same id are replaced.
export async function restoreSnapshot(store, snap) {
  let n = 0;
  for (const c of COLLECTIONS) {
    for (const r of Array.isArray(snap?.[c]) ? snap[c] : []) {
      if (!r || !ID_RE.test(String(r.id))) continue;
      await store.setJSON(`${c}/${r.id}`, r);
      if (r.refHash) await store.setJSON(`refs/${r.refHash}`, { c, id: r.id });
      n++;
    }
  }
  return n;
}

const withoutRef = (r) => { const { refHash: _drop, ...rest } = r; return rest; };
const withoutPii = (r) => { const out = withoutRef(r); for (const f of PII_FIELDS) delete out[f]; return out; };

function csvCell(v) {
  if (v === null || v === undefined) return "";
  let s = typeof v === "object" ? JSON.stringify(v) : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`; // stops spreadsheets running a cell as a formula
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
export function toCsv(rows) {
  const cols = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!cols.includes(k)) cols.push(k);
  const lines = [cols.map(csvCell).join(",")];
  for (const r of rows) lines.push(cols.map((k) => csvCell(r[k])).join(","));
  return "﻿" + lines.join("\r\n") + "\r\n";
}

export function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$16384$8$1$${salt.toString("hex")}$${hash.toString("hex")}`;
}
function verifyPassword(password, stored) {
  try {
    const [alg, N, r, p, saltHex, hashHex] = String(stored).split("$");
    if (alg !== "scrypt") return false;
    const expected = Buffer.from(hashHex, "hex");
    const actual = scryptSync(String(password), Buffer.from(saltHex, "hex"), expected.length, { N: +N, r: +r, p: +p });
    return timingSafeEqual(actual, expected);
  } catch { return false; }
}
const DUMMY_HASH = hashPassword("not-a-real-password"); // keeps timing similar for unknown users

function parseCookies(header = "") {
  const out = {};
  for (const part of String(header).split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
const cookie = (value, maxAge) => `aim_session=${value}; HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=${maxAge}`;

export function createApi({ store, env = {}, fetchFn = globalThis.fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), now = () => Date.now() }) {
  const ownerId = String(env.OWNER_USER_ID || "").trim().toLowerCase();
  const adminEnabled = !!(ownerId && env.OWNER_PASSWORD && env.SESSION_SECRET && String(env.SESSION_SECRET).length >= 32);

  const readJson = (key) => store.get(key, { type: "json" });

  const readAll = (collection) => readCollection(store, collection);

  // Compare-and-swap update: read the record with its version tag, compute the new value, and write
  // only if nobody else changed it in between. Return undefined from `fn` to leave it unchanged.
  async function casUpdate(key, fn, tries = 12) {
    for (let i = 0; i < tries; i++) {
      const cur = await store.getWithMetadata(key, { type: "json" });
      const next = fn(cur ? cur.data : null);
      if (next === undefined) return null;
      const res = cur && cur.etag
        ? await store.setJSON(key, next, { onlyIfMatch: cur.etag })
        : await store.setJSON(key, next, { onlyIfNew: true });
      if (res && res.modified !== false) return next;
      await sleep(Math.floor(Math.random() * 20 * (i + 1))); // small random pause so competing requests spread out
    }
    throw new Error("contention");
  }

  // ---- rate limiting (counters kept in the store, keyed by a hash of the IP) ----
  const ipHash = (ip) => createHash("sha256").update(`aimpact|${ip || "unknown"}`).digest("hex").slice(0, 24);
  async function sweep() {
    try {
      const { blobs } = await store.list({ prefix: "rl/" });
      for (const b of blobs) {
        const v = await readJson(b.key);
        if (!v || v.exp < now()) await store.delete(b.key);
      }
    } catch { /* best effort */ }
  }
  const rlKey = (scope, id, windowMs) => `rl/${scope}/${id}/${Math.floor(now() / windowMs)}`;
  // Reserves one use. Because the update is atomic, parallel requests cannot slip past the limit.
  async function hit(scope, id, limit, windowMs) {
    const bucket = Math.floor(now() / windowMs);
    let allowed = false;
    try {
      await casUpdate(rlKey(scope, id, windowMs), (cur) => {
        const c = cur || { n: 0, exp: (bucket + 2) * windowMs };
        if (c.n >= limit) { allowed = false; return undefined; }
        allowed = true;
        return { ...c, n: c.n + 1 };
      });
    } catch (e) {
      if (e.message === "contention") return false; // too busy: refuse rather than let it through
      throw e;
    }
    if (Math.random() < 0.02) sweep();
    return allowed;
  }
  async function refund(scope, id, windowMs, count = 1) {
    try {
      await casUpdate(rlKey(scope, id, windowMs), (cur) => (cur && cur.n > 0 ? { ...cur, n: Math.max(0, cur.n - count) } : undefined));
    } catch { /* best effort */ }
  }

  // ---- bot checks shared by the public forms ----
  async function botCheck(guard, ip, { requireDelay }) {
    const g = guard && typeof guard === "object" ? guard : {};
    if (g.hp) return { silent: true }; // honeypot filled: pretend success, store nothing
    if (requireDelay) {
      const started = Number(g.startedAt);
      if (!Number.isFinite(started) || started <= 0) return { error: "Please reload the page and try again.", status: 400 };
      if (now() - started < MIN_FILL_MS) return { error: "That was very quick. Please check your answers and submit again.", status: 400 };
    }
    if (env.TURNSTILE_SECRET) {
      if (!g.token) return { error: "Please complete the verification check.", status: 400 };
      try {
        const res = await fetchFn("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: String(g.token), remoteip: String(ip || "") }),
        });
        const out = await res.json();
        if (!out.success) return { error: "The verification check failed. Please try again.", status: 400 };
      } catch {
        return { error: "Could not run the verification check. Please try again.", status: 503 };
      }
    }
    return {};
  }

  // ---- sessions ----
  const sign = (payload) => {
    const body = b64(JSON.stringify(payload));
    return `${body}.${b64(createHmac("sha256", env.SESSION_SECRET).update(body).digest())}`;
  };
  function open(token) {
    if (typeof token !== "string") return null;
    const [body, sig] = token.split(".");
    if (!body || !sig) return null;
    const expected = b64(createHmac("sha256", env.SESSION_SECRET).update(body).digest());
    if (!safeEqual(sig, expected)) return null;
    let p;
    try { p = JSON.parse(Buffer.from(body, "base64url").toString()); } catch { return null; }
    return p && p.e >= now() ? p : null;
  }
  // A "ticket" proves the password step passed. It is not a session and opens nothing by itself.
  const ticketFor = (session, enrolled) => sign({ r: "pre", u: session.u, n: session.n, ro: session.r, en: enrolled, e: now() + TICKET_MINUTES * 60_000 });
  const openTicket = (t) => { const p = open(t); return p && p.r === "pre" ? p : null; };

  // Two-step state for one person. The owner can ask for a reset from the site settings.
  async function twofaState(id) {
    const rec = await readJson(`twofa/${id}`);
    if (rec && id === ownerId && env.OWNER_2FA_RESET && rec.resetMarker !== String(env.OWNER_2FA_RESET)) return null;
    return rec;
  }

  async function sessionFrom(headers) {
    if (!adminEnabled) return null;
    const p = open(parseCookies(headers.cookie).aim_session);
    if (!p) return null;
    if (p.r === "admin") {
      const u = await readJson(`admins/${p.u}`);
      if (!u || !u.active) return null; // disabled accounts lose access at once
      return { id: u.id, name: u.name, role: "admin" };
    }
    if (p.r === "owner" && p.u === ownerId) return { id: ownerId, name: p.n || ownerId, role: "owner" };
    return null;
  }

  async function audit(user, action, detail = {}) {
    const at = new Date(now()).toISOString();
    await store.setJSON(`audit/${at}-${randomBytes(3).toString("hex")}`, { at, by: user.id, action, ...detail });
  }

  // ---- sign-in attempts: counted before the check, handed back after a full successful sign-in ----
  const LOGIN_WINDOW = 15 * 60_000;
  async function reserveLogin(who, userId) {
    const a = await hit("login-ip", who, 8, LOGIN_WINDOW);
    const b = await hit("login-user", ipHash(userId), 10, LOGIN_WINDOW);
    return a && b;
  }
  async function finishLogin(session, who, action) {
    const token = sign({ u: session.u, r: session.r, n: session.n, e: now() + SESSION_HOURS * 3_600_000 });
    await audit({ id: session.u }, action);
    await refund("login-ip", who, LOGIN_WINDOW, 2);
    await refund("login-user", ipHash(session.u), LOGIN_WINDOW, 2);
    return { status: 200, body: { user: { id: session.u, name: session.n, role: session.r } }, cookies: [cookie(token, SESSION_HOURS * 3600)] };
  }

  // handle(method, path, body, { headers, ip }) -> { status, body, cookies? } (or { raw, contentType, filename } for downloads)
  return async function handle(method, path, body, { headers = {}, ip = "" } = {}) {
    const parts = path.split("/").filter(Boolean);
    const who = ipHash(ip);
    try {
      // ------------------------------------------------ public
      if (method === "GET" && parts[0] === "public" && parts.length === 1) {
        const [p, c, b] = await Promise.all(COLLECTIONS.map(readAll));
        return { status: 200, body: { providers: p.map(publicProvider), consultants: c.map(publicConsultant), briefs: b.map(publicBrief) } };
      }

      if (method === "POST" && parts[0] === "submit" && parts.length === 2) {
        const collection = parts[1];
        if (!COLLECTIONS.includes(collection)) return { status: 404, body: { error: "Not found." } };
        if (!(await hit("submit", who, 10, 3_600_000))) return { status: 429, body: { error: "Too many submissions from this network. Please try again later." } };
        const bot = await botCheck(body?.guard, ip, { requireDelay: true });
        if (bot.silent) return { status: 201, body: { ok: true } };
        if (bot.error) return { status: bot.status, body: { error: bot.error } };
        if (body?.guard?.consent !== true) return { status: 400, body: { error: "Please confirm that you have read the privacy notice." } };
        const { record, error } = sanitiseSubmission(collection, body?.record);
        if (error) return { status: 400, body: { error } };
        record.consentAt = new Date(now()).toISOString();
        record.noticeVersion = NOTICE_VERSION;
        if (JSON.stringify(record).length > MAX_RECORD_BYTES) return { status: 413, body: { error: "Submission too large." } };
        const code = newRefCode();
        record.refHash = refHash(code);
        await store.setJSON(`refs/${record.refHash}`, { c: collection, id: record.id });
        await store.setJSON(`${collection}/${record.id}`, record);
        return { status: 201, body: { ok: true, id: record.id, ref: formatRef(code) } };
      }

      // Status needs the reference code given at submission AND the email, and says nothing else.
      if (method === "POST" && parts[0] === "status" && parts.length === 1) {
        const notFound = { status: 404, body: { error: "We could not find an application or brief with that reference code and email." } };
        if (!(await hit("status", who, 20, 3_600_000))) return { status: 429, body: { error: "Too many checks from this network. Please try again later." } };
        const bot = await botCheck(body?.guard, ip, { requireDelay: false });
        if (bot.silent) return notFound;
        if (bot.error) return { status: bot.status, body: { error: bot.error } };
        const code = normaliseRef(body?.ref);
        const email = text(body?.email).toLowerCase();
        if (!code) return { status: 400, body: { error: "Please enter the reference code you were given, like AIM-ABCDE-12345." } };
        if (!EMAIL_RE.test(email)) return { status: 400, body: { error: "Please enter a valid email address." } };
        const idx = await readJson(`refs/${refHash(code)}`);
        const rec = idx && COLLECTIONS.includes(idx.c) && ID_RE.test(String(idx.id)) ? await readJson(`${idx.c}/${idx.id}`) : null;
        if (!rec || String(rec.contactEmail || "").toLowerCase() !== email) return notFound;
        const item = idx.c === "briefs"
          ? { orgName: rec.orgName, stage: rec.stage, outcomeStatus: rec.outcomeStatus, selectedProviderName: rec.selectedProviderName }
          : { name: rec.name, status: rec.status, tier: rec.tier, totalScore: rec.totalScore };
        return { status: 200, body: { kind: idx.c, item } };
      }

      // ------------------------------------------------ admin
      if (parts[0] === "admin") {
        if (!adminEnabled) return { status: 503, body: { error: "Admin access is not configured." } };

        if (method === "POST" && parts[1] === "login" && parts.length === 2) {
          if (headers["x-requested-with"] !== "aimpact") return { status: 403, body: { error: "Forbidden." } };
          const userId = text(body?.userId).toLowerCase();
          const password = typeof body?.password === "string" ? body.password : "";
          // Every attempt reserves a place in the counters BEFORE the password is checked, so a burst of
          // parallel guesses cannot get past the limit. A full successful sign-in gives the places back.
          if (!(await reserveLogin(who, userId))) {
            return { status: 429, body: { error: "Too many failed attempts. Please wait 15 minutes and try again." } };
          }
          let session = null;
          if (userId && userId === ownerId) {
            if (safeEqual(password, env.OWNER_PASSWORD)) session = { u: ownerId, r: "owner", n: ownerId };
          } else if (USER_RE.test(userId)) {
            const u = await readJson(`admins/${userId}`);
            const ok = verifyPassword(password, u ? u.hash : DUMMY_HASH);
            if (u && u.active && ok) session = { u: u.id, r: "admin", n: u.name };
          } else {
            verifyPassword(password, DUMMY_HASH);
          }
          if (!session) {
            await sleep(400);
            return { status: 401, body: { error: "Incorrect user ID or password." } };
          }
          // Password is right. A code from the authenticator app is still needed (or first-time setup).
          const st = await twofaState(session.u);
          const enrolled = !!(st && st.enabled && st.secret);
          return { status: 200, body: { step: enrolled ? "code" : "enroll", ticket: ticketFor(session, enrolled) } };
        }

        // Second step: the 6-digit code from the authenticator app.
        if (method === "POST" && parts[1] === "login" && parts[2] === "verify" && parts.length === 3) {
          if (headers["x-requested-with"] !== "aimpact") return { status: 403, body: { error: "Forbidden." } };
          const t = openTicket(body?.ticket);
          if (!t || !t.en) return { status: 401, body: { error: "Your sign-in timed out. Please start again." } };
          if (!(await reserveLogin(who, t.u))) return { status: 429, body: { error: "Too many failed attempts. Please wait 15 minutes and try again." } };
          const st = await twofaState(t.u);
          if (!st || !st.enabled || !st.secret) return { status: 401, body: { error: "Your sign-in timed out. Please start again." } };
          if (t.ro === "admin") {
            const u = await readJson(`admins/${t.u}`);
            if (!u || !u.active) return { status: 401, body: { error: "Your sign-in timed out. Please start again." } };
          }
          const step = checkTotp(st.secret, body?.code, st.lastStep, now());
          if (step === null) { await sleep(400); return { status: 401, body: { error: "That code is not correct, or it was already used. Wait for the next code and try again." } }; }
          // a code works once: record the step it belonged to
          let claimed = false;
          await casUpdate(`twofa/${t.u}`, (cur) => {
            if (!cur || (cur.lastStep || 0) >= step) { claimed = false; return undefined; }
            claimed = true; return { ...cur, lastStep: step };
          });
          if (!claimed) { await sleep(400); return { status: 401, body: { error: "That code is not correct, or it was already used. Wait for the next code and try again." } }; }
          return finishLogin({ u: t.u, r: t.ro, n: t.n }, who, "login");
        }

        // First sign-in with two-step: show the secret to add to an authenticator app.
        if (method === "POST" && parts[1] === "2fa" && parts[2] === "setup" && parts.length === 3) {
          if (headers["x-requested-with"] !== "aimpact") return { status: 403, body: { error: "Forbidden." } };
          const t = openTicket(body?.ticket);
          if (!t || t.en) return { status: 401, body: { error: "Your sign-in timed out. Please start again." } };
          if ((await twofaState(t.u))?.enabled) return { status: 409, body: { error: "Two-step sign-in is already set up. Please sign in again." } };
          const fresh = base32Encode(randomBytes(20));
          const rec = await casUpdate(`twofa/${t.u}`, (cur) => (cur && !cur.enabled && cur.pending ? undefined : { pending: fresh, enabled: false, lastStep: 0 }));
          const pending = rec ? rec.pending : (await readJson(`twofa/${t.u}`)).pending;
          const label = encodeURIComponent(`AImpact StartupTN:${t.u}`);
          return { status: 200, body: { secret: pending, uri: `otpauth://totp/${label}?secret=${pending}&issuer=${encodeURIComponent("AImpact StartupTN")}&algorithm=SHA1&digits=6&period=30` } };
        }

        if (method === "POST" && parts[1] === "2fa" && parts[2] === "enable" && parts.length === 3) {
          if (headers["x-requested-with"] !== "aimpact") return { status: 403, body: { error: "Forbidden." } };
          const t = openTicket(body?.ticket);
          if (!t || t.en) return { status: 401, body: { error: "Your sign-in timed out. Please start again." } };
          if (!(await reserveLogin(who, t.u))) return { status: 429, body: { error: "Too many failed attempts. Please wait 15 minutes and try again." } };
          const raw = await readJson(`twofa/${t.u}`);
          if (!raw || raw.enabled === true && !(t.u === ownerId && env.OWNER_2FA_RESET && raw.resetMarker !== String(env.OWNER_2FA_RESET))) {
            return { status: 409, body: { error: "Please reload the page and start again." } };
          }
          if (!raw.pending) return { status: 409, body: { error: "Please reload the page and start again." } };
          const step = checkTotp(raw.pending, body?.code, 0, now());
          if (step === null) { await sleep(400); return { status: 401, body: { error: "That code is not correct. Check the app and try again." } }; }
          await store.setJSON(`twofa/${t.u}`, {
            secret: raw.pending, enabled: true, lastStep: step, enabledAt: new Date(now()).toISOString(),
            ...(t.u === ownerId && env.OWNER_2FA_RESET ? { resetMarker: String(env.OWNER_2FA_RESET) } : {}),
          });
          return finishLogin({ u: t.u, r: t.ro, n: t.n }, who, "2fa-enrolled");
        }

        if (method === "POST" && parts[1] === "logout" && parts.length === 2) {
          return { status: 200, body: { ok: true }, cookies: [cookie("", 0)] };
        }

        const user = await sessionFrom(headers);
        if (!user) return { status: 401, body: { error: "Please sign in." } };
        if (method !== "GET" && headers["x-requested-with"] !== "aimpact") return { status: 403, body: { error: "Forbidden." } };
        const ownerOnly = () => (user.role === "owner" ? null : { status: 403, body: { error: "Only the owner can do this." } });

        if (method === "GET" && parts[1] === "me" && parts.length === 2) return { status: 200, body: { user } };

        // The lists carry no contact details; those come one record at a time and are logged.
        if (method === "GET" && parts[1] === "data" && parts.length === 2) {
          const [providers, consultants, briefs] = await Promise.all(COLLECTIONS.map(readAll));
          await audit(user, "load-data", { providers: providers.length, consultants: consultants.length, briefs: briefs.length });
          return { status: 200, body: { providers: providers.map(withoutPii), consultants: consultants.map(withoutPii), briefs: briefs.map(withoutPii) } };
        }

        if (parts[1] === "record" && parts.length === 4) {
          const [, , collection, id] = parts;
          if (!COLLECTIONS.includes(collection) || !ID_RE.test(id)) return { status: 404, body: { error: "Not found." } };
          const existing = await readJson(`${collection}/${id}`);
          if (!existing) return { status: 404, body: { error: "Record not found." } };
          if (method === "GET") {
            if (!(await hit("view", ipHash(user.id), 120, 3_600_000))) return { status: 429, body: { error: "You have opened a lot of records this hour. Please try again later." } };
            await audit(user, "view", { collection, id });
            return { status: 200, body: { record: withoutRef(existing) } };
          }
          if (method === "PUT") {
            const record = body?.record;
            if (!record || typeof record !== "object" || record.id !== id) return { status: 400, body: { error: "Invalid record." } };
            if (JSON.stringify(record).length > MAX_RECORD_BYTES * 2) return { status: 413, body: { error: "Record too large." } };
            // Staff decisions never overwrite contact details, consent evidence or the reference code.
            const merged = { ...record };
            for (const f of PROTECTED_FIELDS) { if (existing[f] !== undefined) merged[f] = existing[f]; else delete merged[f]; }
            const stamped = { ...merged, updatedBy: user.id, updatedAt: new Date(now()).toISOString() };
            await store.setJSON(`${collection}/${id}`, stamped);
            await audit(user, "update", { collection, id });
            return { status: 200, body: { ok: true } };
          }
          if (method === "DELETE") {
            const denied = ownerOnly();
            if (denied) return denied;
            await store.delete(`${collection}/${id}`);
            if (existing.refHash) await store.delete(`refs/${existing.refHash}`);
            await audit(user, "delete", { collection, id });
            return { status: 200, body: { ok: true } };
          }
        }

        // Owner: find everything held about a person (for access, correction and deletion requests).
        if (method === "POST" && parts[1] === "search" && parts.length === 2) {
          const denied = ownerOnly();
          if (denied) return denied;
          const needle = text(body?.q).toLowerCase();
          if (needle.length < 3) return { status: 400, body: { error: "Type at least 3 characters." } };
          if (!(await hit("search", ipHash(user.id), 60, 3_600_000))) return { status: 429, body: { error: "Too many searches this hour. Please try again later." } };
          const all = await Promise.all(COLLECTIONS.map(readAll));
          const rows = [];
          COLLECTIONS.forEach((c, i) => {
            for (const r of all[i]) {
              if ([r.contactEmail, r.phone, r.name, r.orgName, r.contactName].some((v) => String(v || "").toLowerCase().includes(needle))) {
                rows.push({ collection: c, record: withoutRef(r) });
              }
            }
          });
          const out = rows.slice(0, 25);
          await audit(user, "search", { results: out.length }); // what was typed is not stored
          return { status: 200, body: { rows: out, more: rows.length > out.length } };
        }

        // Owner: download everything. JSON for the whole set, or CSV for one list.
        if (method === "GET" && parts[1] === "export" && parts.length === 3) {
          const denied = ownerOnly();
          if (denied) return denied;
          const file = parts[2];
          const m = /^(all\.json|(providers|consultants|briefs)\.csv)$/.exec(file);
          if (!m) return { status: 404, body: { error: "Not found." } };
          if (!(await hit("export", ipHash(user.id), 20, 3_600_000))) return { status: 429, body: { error: "Too many exports this hour. Please try again later." } };
          const stamp = new Date(now()).toISOString().slice(0, 10);
          await audit(user, "export", { file });
          if (file === "all.json") {
            const snap = await snapshot(store, now());
            const clean = { ...snap, providers: snap.providers.map(withoutRef), consultants: snap.consultants.map(withoutRef), briefs: snap.briefs.map(withoutRef) };
            return { status: 200, raw: JSON.stringify(clean, null, 2), contentType: "application/json; charset=utf-8", filename: `aimpact-export-${stamp}.json` };
          }
          const rows = (await readAll(m[2])).map(withoutRef);
          return { status: 200, raw: toCsv(rows), contentType: "text/csv; charset=utf-8", filename: `aimpact-${m[2]}-${stamp}.csv` };
        }

        if (parts[1] === "users") {
          const denied = ownerOnly();
          if (denied) return denied;
          if (method === "GET" && parts.length === 2) {
            const { blobs } = await store.list({ prefix: "admins/" });
            const rows = (await Promise.all(blobs.map((b) => readJson(b.key)))).filter(Boolean);
            const users = await Promise.all(rows.map(async (u) => ({
              id: u.id, name: u.name, active: u.active, createdAt: u.createdAt, createdBy: u.createdBy,
              twoFactor: !!(await readJson(`twofa/${u.id}`))?.enabled,
            })));
            return { status: 200, body: { owner: ownerId, users } };
          }
          if (method === "POST" && parts.length === 2) {
            const id = text(body?.userId).toLowerCase();
            const name = text(body?.name).slice(0, 80);
            const password = typeof body?.password === "string" ? body.password : "";
            if (!USER_RE.test(id)) return { status: 400, body: { error: "User ID must be 3 to 32 characters: lowercase letters, numbers, dot, dash or underscore." } };
            if (id === ownerId) return { status: 400, body: { error: "That user ID is reserved." } };
            if (!name) return { status: 400, body: { error: "Please enter the person's name." } };
            if (password.length < 12 || password.length > 200) return { status: 400, body: { error: "Password must be at least 12 characters." } };
            if (await readJson(`admins/${id}`)) return { status: 409, body: { error: "That user ID already exists." } };
            await store.setJSON(`admins/${id}`, { id, name, hash: hashPassword(password), active: true, createdAt: new Date(now()).toISOString(), createdBy: user.id });
            await audit(user, "create-user", { id });
            return { status: 201, body: { ok: true } };
          }
          if (method === "PUT" && parts.length === 3) {
            const id = parts[2];
            const u = USER_RE.test(id) ? await readJson(`admins/${id}`) : null;
            if (!u) return { status: 404, body: { error: "User not found." } };
            if (typeof body?.active === "boolean") u.active = body.active;
            if (body?.password !== undefined) {
              if (typeof body.password !== "string" || body.password.length < 12 || body.password.length > 200) return { status: 400, body: { error: "Password must be at least 12 characters." } };
              u.hash = hashPassword(body.password);
            }
            await store.setJSON(`admins/${id}`, u);
            if (body?.reset2fa === true) await store.delete(`twofa/${id}`); // they set it up again at next sign-in
            await audit(user, "update-user", { id, active: u.active, passwordReset: body?.password !== undefined, twoFactorReset: body?.reset2fa === true });
            return { status: 200, body: { ok: true } };
          }
        }

        if (method === "GET" && parts[1] === "audit" && parts.length === 2) {
          const denied = ownerOnly();
          if (denied) return denied;
          const { blobs } = await store.list({ prefix: "audit/" });
          const keys = blobs.map((b) => b.key).sort().slice(-100).reverse();
          const items = (await Promise.all(keys.map((k) => readJson(k)))).filter(Boolean);
          return { status: 200, body: { items } };
        }
      }

      return { status: 404, body: { error: "Not found." } };
    } catch (err) {
      console.error("API error", method, path, err);
      return { status: 500, body: { error: "Something went wrong." } };
    }
  };
}
