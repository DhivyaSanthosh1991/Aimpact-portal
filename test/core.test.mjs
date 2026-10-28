import test from "node:test";
import assert from "node:assert/strict";
import {
  createApi, totpCode, base32Encode, normaliseRef, runBackup, restoreSnapshot, snapshot, toCsv,
} from "../netlify/lib/core.mjs";
import { memoryStore } from "../test-support/memory-store.mjs";

const ENV = { OWNER_USER_ID: "Owner", OWNER_PASSWORD: "owner-password-123", SESSION_SECRET: "x".repeat(40) };
let clock = 1_800_000_000_000;
function setup(extraEnv = {}, fetchFn, store = memoryStore()) {
  const api = createApi({ store, env: { ...ENV, ...extraEnv }, fetchFn, sleep: async () => {}, now: () => clock });
  api.store = store;
  return api;
}
const IP = { ip: "10.0.0.1" };
const XR = { "x-requested-with": "aimpact" };
const guard = (extra = {}) => ({ hp: "", startedAt: clock - 30_000, consent: true, ...extra });

const provider = {
  contactName: "Asha", designation: "CEO", contactEmail: "Asha@Example.com", phone: "9876543210",
  name: "Acme AI", category: "Tool Builder", sector: "Health AI", capabilities: ["x"],
  description: "We built a thing", smeApproach: "We would do a thing", demoLink: "https://d.example", ref1: "A client, 99999",
  status: "Verified", totalScore: 100, // attempt to self-verify
};
const submit = (api, rec = provider, g = guard(), ctx = IP) => api("POST", "/submit/providers", { record: rec, guard: g }, ctx);

// ---- helpers for the two-step sign-in ----
const secrets = new Map(); // "<api id>|<user>" -> authenticator secret
let apiCounter = 0;
const idOf = (api) => (api.uid ??= ++apiCounter);
const step = () => Math.floor(clock / 30_000);
const cookieOf = (r) => (r.cookies ? r.cookies[0].split(";")[0] : "");

// Full sign-in: password, then either first-time setup or the code. Moves the clock on by one
// 30-second step first so each code is a new one (a code works only once).
async function login(api, userId = "owner", password = ENV.OWNER_PASSWORD, ip = "10.9.9.9") {
  const r1 = await api("POST", "/admin/login", { userId, password }, { headers: XR, ip });
  if (r1.status !== 200) return { r: r1, headers: {}, ip };
  clock += 30_000;
  const key = `${idOf(api)}|${userId.toLowerCase()}`;
  let r;
  if (r1.body.step === "enroll") {
    const s = await api("POST", "/admin/2fa/setup", { ticket: r1.body.ticket }, { headers: XR, ip });
    secrets.set(key, s.body.secret);
    r = await api("POST", "/admin/2fa/enable", { ticket: r1.body.ticket, code: totpCode(s.body.secret, step()) }, { headers: XR, ip });
  } else {
    r = await api("POST", "/admin/login/verify", { ticket: r1.body.ticket, code: totpCode(secrets.get(key), step()) }, { headers: XR, ip });
  }
  return { r, first: r1, headers: { cookie: cookieOf(r), ...XR }, ip };
}

// ------------------------------------------------ building blocks
test("authenticator codes match the RFC 6238 test values", () => {
  const secret = base32Encode(Buffer.from("12345678901234567890"));
  assert.equal(totpCode(secret, 1), "287082");            // t = 59
  assert.equal(totpCode(secret, 37037036), "081804");     // t = 1111111109
});

test("reference codes accept spacing, case and the AIM prefix", () => {
  assert.equal(normaliseRef("aim-abcde-23456"), "ABCDE23456");
  assert.equal(normaliseRef("ABCDE 23456"), "ABCDE23456");
  assert.equal(normaliseRef("ABCDE2345"), "");
  assert.equal(normaliseRef("ABCDE2345O"), ""); // O is not in the alphabet
});

test("CSV export neutralises spreadsheet formulas and quotes properly", () => {
  const out = toCsv([{ a: "=SUM(1,2)", b: 'say "hi", ok', c: "+91 98765", d: ["x"] }]);
  assert.ok(out.includes("'=SUM(1,2)"));
  assert.ok(out.includes('"say ""hi"", ok"'));
  assert.ok(out.includes("'+91 98765"));
  assert.ok(out.includes('["x"]'.replace(/"/g, '""')));
});

// ------------------------------------------------ public submissions
test("submission is forced to Pending, never self-verifies, records consent and gives a reference code", async () => {
  const api = setup();
  const s = await submit(api);
  assert.equal(s.status, 201);
  assert.match(s.body.ref, /^AIM-[A-Z0-9]{5}-[A-Z0-9]{5}$/);
  const { headers } = await login(api);
  const all = await api("GET", "/admin/data", null, { headers });
  const p = all.body.providers[0];
  assert.equal(p.status, "Pending");
  assert.equal(p.totalScore, 0);
  assert.equal(p.noticeVersion, "1.1");
  assert.ok(p.consentAt);
});

test("consent is required", async () => {
  const api = setup();
  const r = await submit(api, provider, guard({ consent: false }));
  assert.equal(r.status, 400);
  assert.match(r.body.error, /privacy notice/);
});

test("honeypot silently drops bot submissions", async () => {
  const api = setup();
  const r = await submit(api, provider, guard({ hp: "http://spam.example" }));
  assert.equal(r.status, 201);
  assert.equal(r.body.ref, undefined);
  const { headers } = await login(api);
  assert.equal((await api("GET", "/admin/data", null, { headers })).body.providers.length, 0);
});

test("forms submitted faster than a human can fill them are refused", async () => {
  const api = setup();
  assert.equal((await submit(api, provider, guard({ startedAt: clock - 500 }))).status, 400);
  assert.equal((await submit(api, provider, guard({ startedAt: undefined }))).status, 400);
});

test("per-IP rate limit on submissions", async () => {
  const api = setup();
  let last;
  for (let i = 0; i < 11; i++) last = await submit(api, provider, guard(), { ip: "10.1.1.1" });
  assert.equal(last.status, 429);
  assert.equal((await submit(api, provider, guard(), { ip: "10.2.2.2" })).status, 201); // other networks unaffected
});

test("rate limit holds when requests arrive at the same moment", async () => {
  const api = setup({}, undefined, memoryStore({ slow: true }));
  const results = await Promise.all(Array.from({ length: 30 }, () => submit(api, provider, guard(), { ip: "10.3.3.3" })));
  const ok = results.filter((r) => r.status === 201).length;
  const blocked = results.filter((r) => r.status === 429).length;
  assert.ok(ok <= 10, `${ok} got through`);   // never more than the limit; a few may be turned away under heavy contention
  assert.ok(ok >= 5);
  assert.equal(ok + blocked, 30);
});

test("password guesses sent in parallel cannot get past the lockout", async () => {
  const api = setup({}, undefined, memoryStore({ slow: true }));
  const results = await Promise.all(Array.from({ length: 40 }, (_, i) =>
    api("POST", "/admin/login", { userId: "owner", password: `wrong-${i}` }, { headers: XR, ip: "6.6.6.6" })));
  assert.equal(results.filter((r) => r.status === 401).length, 8);   // only 8 guesses were ever checked
  assert.equal(results.filter((r) => r.status === 429).length, 32);
});

test("Turnstile is enforced when configured", async () => {
  const calls = [];
  const fetchFn = async (url, opts) => { calls.push(url); const ok = String(opts.body).includes("good"); return { json: async () => ({ success: ok }) }; };
  const api = setup({ TURNSTILE_SECRET: "sec" }, fetchFn);
  assert.equal((await submit(api, provider, guard())).status, 400);
  assert.equal((await submit(api, provider, guard({ token: "bad" }))).status, 400);
  assert.equal((await submit(api, provider, guard({ token: "good" }))).status, 201);
  assert.ok(calls[0].includes("challenges.cloudflare.com"));
});

test("public data hides pending applicants and contact details", async () => {
  const api = setup();
  await submit(api);
  await api("POST", "/submit/consultants", { record: { name: "Ravi", contactEmail: "r@e.com", phone: "1", portfolio: "p" }, guard: guard() }, IP);
  await api("POST", "/submit/briefs", { record: { orgName: "Org", problemStatement: "P", contactEmail: "o@e.com", phone: "1" }, guard: guard() }, IP);
  const r = await api("GET", "/public");
  const text = JSON.stringify(r.body);
  assert.equal(r.status, 200);
  for (const secret of ["Asha", "9876543210", "Acme AI", "r@e.com", "o@e.com", "Org", "refHash"]) assert.ok(!text.includes(secret), secret);
});

// ------------------------------------------------ status by reference code
test("status needs the reference code and the email, and shows limited fields", async () => {
  const api = setup();
  const { body: { ref } } = await submit(api);
  const ok = await api("POST", "/status", { ref, email: "asha@example.com", guard: {} }, IP);
  assert.equal(ok.status, 200);
  assert.equal(ok.body.kind, "providers");
  assert.deepEqual(Object.keys(ok.body.item).sort(), ["name", "status", "tier", "totalScore"]);
  // lower case, no dashes is fine
  assert.equal((await api("POST", "/status", { ref: ref.toLowerCase().replace(/-/g, ""), email: "ASHA@example.com", guard: {} }, IP)).status, 200);
  // email alone no longer works
  assert.equal((await api("POST", "/status", { email: "asha@example.com", guard: {} }, IP)).status, 400);
  // wrong email, wrong code: the same answer, so nothing is revealed
  const wrongEmail = await api("POST", "/status", { ref, email: "someone@else.com", guard: {} }, IP);
  const wrongRef = await api("POST", "/status", { ref: "AIM-AAAAA-AAAAA", email: "asha@example.com", guard: {} }, IP);
  assert.equal(wrongEmail.status, 404);
  assert.deepEqual(wrongEmail.body, wrongRef.body);
  assert.equal((await api("POST", "/status", { ref, email: "bad", guard: {} }, IP)).status, 400);
});

test("status checks are rate limited", async () => {
  const api = setup();
  let last;
  for (let i = 0; i < 25; i++) last = await api("POST", "/status", { ref: "AIM-AAAAA-AAAAA", email: "n@e.com", guard: {} }, { ip: "10.5.5.5" });
  assert.equal(last.status, 429);
});

test("briefs and expert validators have reference codes too", async () => {
  const api = setup();
  const b = await api("POST", "/submit/briefs", { record: { orgName: "Org", problemStatement: "P", contactEmail: "o@e.com", phone: "1" }, guard: guard() }, IP);
  const r = await api("POST", "/status", { ref: b.body.ref, email: "o@e.com", guard: {} }, IP);
  assert.equal(r.body.kind, "briefs");
  assert.equal(r.body.item.stage, "Discovery");
});

// ------------------------------------------------ admin sign-in with two steps
test("admin routes need a signed-in session", async () => {
  const api = setup();
  assert.equal((await api("GET", "/admin/data", null, { headers: {} })).status, 401);
  assert.equal((await api("GET", "/admin/data", null, { headers: { cookie: "aim_session=forged.value" } })).status, 401);
  const { headers } = await login(api);
  assert.equal((await api("GET", "/admin/data", null, { headers })).status, 200);
});

test("the password alone does not open a session; the first sign-in sets up the authenticator", async () => {
  const api = setup();
  const r = await api("POST", "/admin/login", { userId: "owner", password: ENV.OWNER_PASSWORD }, { headers: XR, ip: "2.2.2.2" });
  assert.equal(r.status, 200);
  assert.equal(r.body.step, "enroll");
  assert.equal(r.cookies, undefined);
  // a ticket is not a session
  assert.equal((await api("GET", "/admin/data", null, { headers: { cookie: `aim_session=${r.body.ticket}` } })).status, 401);
  // wrong code during setup is refused, and nothing is enabled
  const s = await api("POST", "/admin/2fa/setup", { ticket: r.body.ticket }, { headers: XR, ip: "2.2.2.2" });
  assert.match(s.body.uri, /^otpauth:\/\/totp\//);
  assert.equal((await api("POST", "/admin/2fa/enable", { ticket: r.body.ticket, code: "000000" }, { headers: XR, ip: "2.2.2.2" })).status, 401);
  // setup returns the same secret if repeated
  const s2 = await api("POST", "/admin/2fa/setup", { ticket: r.body.ticket }, { headers: XR, ip: "2.2.2.2" });
  assert.equal(s2.body.secret, s.body.secret);
});

test("after setup, each sign-in needs a fresh code; used and wrong codes fail", async () => {
  const api = setup();
  await login(api); // sets up
  const key = `${idOf(api)}|owner`;
  const secret = secrets.get(key);
  const r1 = await api("POST", "/admin/login", { userId: "owner", password: ENV.OWNER_PASSWORD }, { headers: XR, ip: "3.3.3.3" });
  assert.equal(r1.body.step, "code");
  assert.equal((await api("POST", "/admin/login/verify", { ticket: r1.body.ticket, code: "123456" }, { headers: XR, ip: "3.3.3.3" })).status, 401);
  assert.equal((await api("POST", "/admin/login/verify", { ticket: r1.body.ticket, code: "abcdef" }, { headers: XR, ip: "3.3.3.3" })).status, 401);
  clock += 30_000;
  const good = totpCode(secret, step());
  const ok = await api("POST", "/admin/login/verify", { ticket: r1.body.ticket, code: good }, { headers: XR, ip: "3.3.3.3" });
  assert.equal(ok.status, 200);
  assert.match(ok.cookies[0], /HttpOnly; Secure; SameSite=Strict/);
  // the same code cannot be used again
  const r2 = await api("POST", "/admin/login", { userId: "owner", password: ENV.OWNER_PASSWORD }, { headers: XR, ip: "3.3.3.3" });
  const again = await api("POST", "/admin/login/verify", { ticket: r2.body.ticket, code: good }, { headers: XR, ip: "3.3.3.3" });
  assert.equal(again.status, 401);
  assert.match(again.body.error, /already used/);
});

test("a ticket expires, and a session cookie is not a ticket", async () => {
  const api = setup();
  await login(api);
  const r1 = await api("POST", "/admin/login", { userId: "owner", password: ENV.OWNER_PASSWORD }, { headers: XR, ip: "4.4.4.4" });
  clock += 6 * 60_000;
  const secret = secrets.get(`${idOf(api)}|owner`);
  assert.equal((await api("POST", "/admin/login/verify", { ticket: r1.body.ticket, code: totpCode(secret, step()) }, { headers: XR, ip: "4.4.4.4" })).status, 401);
  const { r } = await login(api);
  const sessionToken = r.cookies[0].split(";")[0].split("=")[1];
  assert.equal((await api("POST", "/admin/login/verify", { ticket: sessionToken, code: "123456" }, { headers: XR, ip: "4.4.4.4" })).status, 401);
});

test("login needs the right user ID and password", async () => {
  const api = setup();
  assert.equal((await login(api, "owner", "wrong")).r.status, 401);
  assert.equal((await login(api, "nobody", ENV.OWNER_PASSWORD)).r.status, 401);
  const ok = await login(api, "OWNER", ENV.OWNER_PASSWORD); // user id is case-insensitive
  assert.equal(ok.r.status, 200);
});

test("login requires the CSRF header and locks out repeated failures", async () => {
  const api = setup();
  assert.equal((await api("POST", "/admin/login", { userId: "owner", password: ENV.OWNER_PASSWORD }, { headers: {}, ip: "1.1.1.1" })).status, 403);
  let last;
  for (let i = 0; i < 9; i++) last = (await login(api, "owner", "wrong", "7.7.7.7")).r;
  assert.equal(last.status, 429);
  assert.equal((await login(api, "owner", ENV.OWNER_PASSWORD, "7.7.7.7")).r.status, 429); // even the right password is blocked while locked
});

test("a successful sign-in does not use up the allowance", async () => {
  const api = setup();
  for (let i = 0; i < 12; i++) assert.equal((await login(api, "owner", ENV.OWNER_PASSWORD, "8.8.8.8")).r.status, 200);
});

test("admin is disabled when not configured", async () => {
  const api = createApi({ store: memoryStore(), env: {}, sleep: async () => {}, now: () => clock });
  assert.equal((await api("POST", "/admin/login", { userId: "a", password: "b" }, { headers: XR })).status, 503);
});

test("owner can reset the owner's two-step sign-in from the site settings", async () => {
  const store = memoryStore();
  const a1 = setup({}, undefined, store);
  await login(a1);
  assert.equal((await a1("POST", "/admin/login", { userId: "owner", password: ENV.OWNER_PASSWORD }, { headers: XR, ip: "5.5.5.5" })).body.step, "code");
  const a2 = setup({ OWNER_2FA_RESET: "reset-1" }, undefined, store);
  const r = await a2("POST", "/admin/login", { userId: "owner", password: ENV.OWNER_PASSWORD }, { headers: XR, ip: "5.5.5.5" });
  assert.equal(r.body.step, "enroll");
  const s = await a2("POST", "/admin/2fa/setup", { ticket: r.body.ticket }, { headers: XR, ip: "5.5.5.5" });
  clock += 30_000;
  assert.equal((await a2("POST", "/admin/2fa/enable", { ticket: r.body.ticket, code: totpCode(s.body.secret, step()) }, { headers: XR, ip: "5.5.5.5" })).status, 200);
  // the marker is remembered, so the next sign-in asks for a code, not setup
  assert.equal((await a2("POST", "/admin/login", { userId: "owner", password: ENV.OWNER_PASSWORD }, { headers: XR, ip: "5.5.5.5" })).body.step, "code");
});

test("state-changing admin calls need the CSRF header", async () => {
  const api = setup();
  await submit(api);
  const { headers } = await login(api);
  const id = (await api("GET", "/admin/data", null, { headers })).body.providers[0].id;
  const noHeader = { cookie: headers.cookie };
  assert.equal((await api("PUT", `/admin/record/providers/${id}`, { record: { id } }, { headers: noHeader })).status, 403);
});

// ------------------------------------------------ contact details are fetched one record at a time
test("lists carry no contact details; opening a record shows them and is logged", async () => {
  const api = setup();
  await submit(api);
  const { headers } = await login(api);
  const listed = (await api("GET", "/admin/data", null, { headers })).body.providers[0];
  for (const f of ["contactName", "designation", "contactEmail", "phone", "ref1", "refHash"]) assert.equal(listed[f], undefined, f);
  assert.equal(listed.name, "Acme AI");
  const full = await api("GET", `/admin/record/providers/${listed.id}`, null, { headers });
  assert.equal(full.body.record.contactEmail, "Asha@Example.com");
  assert.equal(full.body.record.phone, "9876543210");
  assert.equal(full.body.record.refHash, undefined);
  const log = (await api("GET", "/admin/audit", null, { headers })).body.items;
  assert.ok(log.some((i) => i.action === "view" && i.id === listed.id && i.by === "owner"));
  assert.ok(log.some((i) => i.action === "load-data" && i.providers === 1));
});

test("opening many records is limited per person", async () => {
  const api = setup();
  await submit(api);
  const { headers } = await login(api);
  const id = (await api("GET", "/admin/data", null, { headers })).body.providers[0].id;
  let last;
  for (let i = 0; i < 121; i++) last = await api("GET", `/admin/record/providers/${id}`, null, { headers });
  assert.equal(last.status, 429);
});

test("staff decisions cannot change contact details, consent evidence or the reference code", async () => {
  const api = setup();
  await submit(api);
  const { headers } = await login(api);
  const listed = (await api("GET", "/admin/data", null, { headers })).body.providers[0];
  const before = (await api("GET", `/admin/record/providers/${listed.id}`, null, { headers })).body.record;
  const put = await api("PUT", `/admin/record/providers/${listed.id}`, {
    record: { ...listed, status: "Verified", contactEmail: "evil@x.com", phone: "0", consentAt: "2020-01-01", refHash: "deadbeef", submittedAt: "2000-01-01" },
  }, { headers });
  assert.equal(put.status, 200);
  const after = (await api("GET", `/admin/record/providers/${listed.id}`, null, { headers })).body.record;
  assert.equal(after.status, "Verified");
  for (const f of ["contactEmail", "phone", "consentAt", "submittedAt"]) assert.equal(after[f], before[f], f);
});

test("owner can search for a person; the search text is not logged; staff cannot search", async () => {
  const api = setup();
  await submit(api);
  const owner = await login(api);
  await api("POST", "/admin/users", { userId: "meena", name: "Meena", password: "a-long-password-1" }, { headers: owner.headers });
  const meena = await login(api, "meena", "a-long-password-1");
  assert.equal((await api("POST", "/admin/search", { q: "9876543210" }, { headers: meena.headers })).status, 403);
  assert.equal((await api("POST", "/admin/search", { q: "98" }, { headers: owner.headers })).status, 400);
  const r = await api("POST", "/admin/search", { q: "9876543210" }, { headers: owner.headers });
  assert.equal(r.body.rows.length, 1);
  assert.equal(r.body.rows[0].collection, "providers");
  assert.equal(r.body.rows[0].record.contactEmail, "Asha@Example.com");
  const log = (await api("GET", "/admin/audit", null, { headers: owner.headers })).body.items;
  assert.ok(log.some((i) => i.action === "search" && i.results === 1));
  assert.ok(!JSON.stringify(log).includes("9876543210"));
});

// ------------------------------------------------ admin users, decisions, deletion
test("owner can add admins; admins sign in with two steps, act, and are stamped; disabling cuts access at once", async () => {
  const api = setup();
  const owner = await login(api);
  assert.equal((await api("POST", "/admin/users", { userId: "meena", name: "Meena", password: "short" }, { headers: owner.headers })).status, 400);
  assert.equal((await api("POST", "/admin/users", { userId: "meena", name: "Meena", password: "a-long-password-1" }, { headers: owner.headers })).status, 201);
  assert.equal((await api("POST", "/admin/users", { userId: "meena", name: "Meena", password: "a-long-password-1" }, { headers: owner.headers })).status, 409);

  await submit(api);
  const meena = await login(api, "meena", "a-long-password-1");
  assert.equal(meena.first.body.step, "enroll");
  assert.equal(meena.r.status, 200);
  const p = (await api("GET", "/admin/data", null, { headers: meena.headers })).body.providers[0];
  assert.equal((await api("PUT", `/admin/record/providers/${p.id}`, { record: { ...p, status: "Verified" } }, { headers: meena.headers })).status, 200);
  const stored = (await api("GET", "/admin/data", null, { headers: owner.headers })).body.providers[0];
  assert.equal(stored.updatedBy, "meena");

  // admins cannot manage users, export, or delete records
  assert.equal((await api("GET", "/admin/users", null, { headers: meena.headers })).status, 403);
  assert.equal((await api("GET", "/admin/export/all.json", null, { headers: meena.headers })).status, 403);
  assert.equal((await api("DELETE", `/admin/record/providers/${p.id}`, null, { headers: meena.headers })).status, 403);

  const list = (await api("GET", "/admin/users", null, { headers: owner.headers })).body.users;
  assert.equal(list[0].twoFactor, true);

  // disabling takes effect on the existing session
  await api("PUT", "/admin/users/meena", { active: false }, { headers: owner.headers });
  assert.equal((await api("GET", "/admin/data", null, { headers: meena.headers })).status, 401);
  assert.equal((await login(api, "meena", "a-long-password-1")).r.status, 401);

  // password reset
  await api("PUT", "/admin/users/meena", { active: true, password: "another-long-pass-2" }, { headers: owner.headers });
  assert.equal((await login(api, "meena", "a-long-password-1")).r.status, 401);
  assert.equal((await login(api, "meena", "another-long-pass-2")).r.status, 200);

  // two-step reset: the next sign-in asks to set up again
  await api("PUT", "/admin/users/meena", { reset2fa: true }, { headers: owner.headers });
  assert.equal((await api("GET", "/admin/users", null, { headers: owner.headers })).body.users[0].twoFactor, false);
  const again = await login(api, "meena", "another-long-pass-2");
  assert.equal(again.first.body.step, "enroll");
  assert.equal(again.r.status, 200);

  const log = await api("GET", "/admin/audit", null, { headers: owner.headers });
  assert.ok(log.body.items.some((i) => i.action === "create-user"));
  assert.ok(log.body.items.some((i) => i.action === "update-user" && i.twoFactorReset === true));
});

test("owner can delete a record and its reference code; verified providers appear publicly without contact details", async () => {
  const api = setup();
  const { body: { ref } } = await submit(api);
  const { headers } = await login(api);
  const p = (await api("GET", "/admin/data", null, { headers })).body.providers[0];
  await api("PUT", `/admin/record/providers/${p.id}`, { record: { ...p, status: "Verified" } }, { headers });
  const pub = (await api("GET", "/public")).body.providers[0];
  assert.equal(pub.name, "Acme AI");
  assert.equal(pub.contactEmail, undefined);
  assert.equal((await api("POST", "/status", { ref, email: "asha@example.com", guard: {} }, IP)).status, 200);
  assert.equal((await api("DELETE", `/admin/record/providers/${p.id}`, null, { headers })).status, 200);
  assert.equal((await api("GET", "/admin/data", null, { headers })).body.providers.length, 0);
  assert.equal((await api("POST", "/status", { ref, email: "asha@example.com", guard: {} }, IP)).status, 404);
  assert.ok(!api.store.keys().some((k) => k.startsWith("refs/")));
});

test("validation: required fields, email, unknown collection", async () => {
  const api = setup();
  assert.equal((await api("POST", "/submit/providers", { record: { name: "x" }, guard: guard() }, IP)).status, 400);
  assert.equal((await api("POST", "/submit/briefs", { record: { orgName: "o", problemStatement: "p", contactEmail: "nope", phone: "1" }, guard: guard() }, IP)).status, 400);
  assert.equal((await api("POST", "/submit/users", { record: {}, guard: guard() }, IP)).status, 404);
});

// ------------------------------------------------ export and backup
test("owner export: JSON and CSV downloads, without internal codes, and logged", async () => {
  const api = setup();
  await submit(api);
  const { headers } = await login(api);
  const j = await api("GET", "/admin/export/all.json", null, { headers });
  assert.equal(j.status, 200);
  assert.match(j.filename, /^aimpact-export-\d{4}-\d{2}-\d{2}\.json$/);
  const data = JSON.parse(j.raw);
  assert.equal(data.providers.length, 1);
  assert.equal(data.providers[0].contactEmail, "Asha@Example.com");
  assert.equal(data.providers[0].refHash, undefined);
  const c = await api("GET", "/admin/export/providers.csv", null, { headers });
  assert.equal(c.status, 200);
  assert.ok(c.raw.startsWith("﻿id,"));
  assert.ok(!c.raw.includes("refHash"));
  assert.equal((await api("GET", "/admin/export/admins.csv", null, { headers })).status, 404);
  const log = (await api("GET", "/admin/audit", null, { headers })).body.items;
  assert.ok(log.some((i) => i.action === "export" && i.file === "all.json"));
});

test("daily backup keeps 14 days, and a restore brings records and reference codes back", async () => {
  const store = memoryStore();
  const backupStore = memoryStore();
  const api = setup({}, undefined, store);
  const { body: { ref } } = await submit(api);
  for (let d = 0; d < 16; d++) await runBackup({ store, backupStore, nowMs: Date.UTC(2026, 10, 1 + d) });
  const days = backupStore.keys().sort();
  assert.equal(days.length, 14);
  assert.equal(days[0], "daily/2026-11-03.json");
  assert.equal(days[13], "daily/2026-11-16.json");

  const snap = await backupStore.get(days[13]);
  assert.equal(snap.providers.length, 1);
  const fresh = memoryStore();
  assert.equal(await restoreSnapshot(fresh, snap), 1);
  const api2 = setup({}, undefined, fresh);
  assert.equal((await api2("POST", "/status", { ref, email: "asha@example.com", guard: {} }, IP)).status, 200);
  assert.equal((await snapshot(fresh)).providers.length, 1);
});
