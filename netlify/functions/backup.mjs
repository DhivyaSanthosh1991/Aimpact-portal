// Runs once a day (Netlify scheduled function). Copies all records into a separate store and
// keeps the last 14 days. This protects against accidental deletion and bad edits; it lives in the
// same Netlify account, so it does not replace downloading the export now and then.
import { getStore } from "@netlify/blobs";
import { runBackup } from "../lib/core.mjs";

export default async () => {
  const result = await runBackup({
    store: getStore({ name: "aimpact", consistency: "strong" }),
    backupStore: getStore({ name: "aimpact-backups", consistency: "strong" }),
  });
  console.log("Backup complete", JSON.stringify(result));
};

export const config = { schedule: "@daily" };
