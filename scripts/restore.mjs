// Restore records from a backup or export file into the live store.
//   NETLIFY_SITE_ID=... NETLIFY_AUTH_TOKEN=... node scripts/restore.mjs aimpact-export-2026-11-01.json
// Records with the same id are replaced; nothing else is touched. Staff accounts are not in backups.
import { readFileSync } from "node:fs";
import { getStore } from "@netlify/blobs";
import { restoreSnapshot } from "../netlify/lib/core.mjs";

const file = process.argv[2];
if (!file || !process.env.NETLIFY_SITE_ID || !process.env.NETLIFY_AUTH_TOKEN) {
  console.error("Usage: NETLIFY_SITE_ID=... NETLIFY_AUTH_TOKEN=... node scripts/restore.mjs <backup.json>");
  process.exit(1);
}
const snap = JSON.parse(readFileSync(file, "utf8"));
const store = getStore({ name: "aimpact", consistency: "strong", siteID: process.env.NETLIFY_SITE_ID, token: process.env.NETLIFY_AUTH_TOKEN });
console.log(`Restored ${await restoreSnapshot(store, snap)} records.`);
