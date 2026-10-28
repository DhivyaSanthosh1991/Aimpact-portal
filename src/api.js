// Client for the Netlify Function in netlify/functions/api.mjs
// Staff sessions use an HttpOnly cookie set by the server; nothing secret is kept in the browser.
async function call(path, { method = "GET", body } = {}) {
  const res = await fetch(path, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(method !== "GET" ? { "x-requested-with": "aimpact" } : {}),
    },
    credentials: "same-origin",
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* no body */ }
  if (!res.ok) {
    const err = new Error((data && data.error) || `Request failed (${res.status})`);
    err.status = res.status;
    err.errorId = data?.errorId;
    throw err;
  }
  return data;
}

// public
export const getPublic = () => call("/api/public");
export const submitRecord = (collection, record, guard) => call(`/api/submit/${collection}`, { method: "POST", body: { record, guard } });
export const checkStatus = (ref, email, guard) => call("/api/status", { method: "POST", body: { ref, email, guard } });

// staff
// sign-in takes two steps: password (returns a short-lived ticket), then an authenticator code
export const adminLogin = (userId, password) => call("/api/admin/login", { method: "POST", body: { userId, password } });
export const adminVerify = (ticket, code) => call("/api/admin/login/verify", { method: "POST", body: { ticket, code } });
export const adminTwofaSetup = (ticket) => call("/api/admin/2fa/setup", { method: "POST", body: { ticket } });
export const adminTwofaEnable = (ticket, code) => call("/api/admin/2fa/enable", { method: "POST", body: { ticket, code } });
export const adminLogout = () => call("/api/admin/logout", { method: "POST" });
export const adminMe = () => call("/api/admin/me");
export const adminLoad = () => call("/api/admin/data");
export const adminRecord = (collection, id) => call(`/api/admin/record/${collection}/${id}`);
export const adminSearch = (q) => call("/api/admin/search", { method: "POST", body: { q } });
export const adminSave = (collection, record) => call(`/api/admin/record/${collection}/${record.id}`, { method: "PUT", body: { record } });
export const adminDelete = (collection, id) => call(`/api/admin/record/${collection}/${id}`, { method: "DELETE" });
export const adminUsers = () => call("/api/admin/users");
export const adminCreateUser = (u) => call("/api/admin/users", { method: "POST", body: u });
export const adminUpdateUser = (id, patch) => call(`/api/admin/users/${id}`, { method: "PUT", body: patch });
export const adminAudit = () => call("/api/admin/audit");

// Owner-only download (JSON for everything, or CSV per list)
export async function adminDownload(file) {
  const res = await fetch(`/api/admin/export/${file}`, { credentials: "same-origin" });
  if (!res.ok) {
    let data = null;
    try { data = await res.json(); } catch { /* no body */ }
    const err = new Error((data && data.error) || `Export failed (${res.status})`);
    err.status = res.status;
    throw err;
  }
  const blob = await res.blob();
  const name = /filename="([^"]+)"/.exec(res.headers.get("content-disposition") || "")?.[1] || file;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
