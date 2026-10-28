# AImpact portal: deployment guide

AI Marketplace for Impact (StartupTN). A React site plus one serverless function on Netlify. Submissions are stored in Netlify Blobs, so every visitor and every staff member sees the same data.

## What is in the package

| Path | Purpose |
| --- | --- |
| `src/App.jsx` | The whole portal: public pages, privacy notice and the Enablement console |
| `src/api.js` | Browser client for the API |
| `netlify/functions/api.mjs` | The API endpoint (`/api/*`) |
| `netlify/functions/backup.mjs` | Runs daily and saves a copy of all records (kept 14 days) |
| `netlify/lib/core.mjs` | API logic: validation, spam protection, sign-in, two-step codes, what the public and staff may see |
| `scripts/restore.mjs` | Puts a backup or export file back into the live store |
| `test/`, `test-support/` | 34 automated tests (`npm test`) |
| `netlify.toml` | Build settings and browser security headers |
| `.env.example` | Every setting, with notes |

## Deploy on Netlify

1. Put this folder in a GitHub repository, or use the Netlify CLI.
2. In Netlify choose **Add new site > Import an existing project** and pick the repository. Build settings come from `netlify.toml`.
3. Before the first deploy, open **Site configuration > Environment variables** and add the settings from `.env.example`. These four are required:
   - `OWNER_USER_ID`, `OWNER_PASSWORD`: the owner's sign-in.
   - `SESSION_SECRET`: at least 32 random characters.
   - `VITE_PRIVACY_CONTACT_EMAIL`: where people send privacy requests.
   The other privacy settings (`VITE_GRIEVANCE_OFFICER`, `VITE_ORG_ADDRESS`, `VITE_RETENTION_PERIOD`) fill in the public privacy notice. Until you set them, the notice shows "[to be added before launch]".
4. Deploy. Open the site, submit a test application (note the reference code), then open **Enablement Layer sign-in** in the footer. Sign in as the owner. The first time, you set up two-step sign-in: scan the QR code with an authenticator app (Google Authenticator, Microsoft Authenticator and similar) and enter the code it shows.
5. In the console, open **Staff accounts** and create an account for each team member. Each person sets up their own authenticator at their first sign-in. Use **Data & exports** to find and delete a person's records, and to download the data.
6. **Smoke test after the first deploy** (see "Not yet tested on a live site" below): submit three test forms in a row, check the status page with the reference code, sign in, open a record, download an export.

### Using a subdomain

Add the domain in Netlify (**Domain management > Add a domain**, for example `aimpact.startuptn.in`) and ask StartupTN's IT team to create a DNS `CNAME` record pointing it at your Netlify site address. Netlify then issues the HTTPS certificate. The staff cookie belongs to that subdomain only, so the main website cannot read it.

## Security features

**Spam protection**
- A hidden trap field that real people never fill in. Bots that do are accepted silently and nothing is stored.
- Forms submitted in under 4 seconds are refused.
- At most 10 submissions and 20 status checks per hour from one network. Networks are tracked as scrambled (hashed) values, deleted automatically. The counters are updated atomically, so a burst of simultaneous requests cannot get past the limit.
- Optional Cloudflare Turnstile CAPTCHA: add `VITE_TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET` and it switches on for every public form.

**Staff sign-in**
- Individual user ID and password for each person. Passwords are stored as salted scrypt hashes, never in plain text.
- **Two-step sign-in is required for everyone, including the owner.** After the password, a 6-digit code from an authenticator app is needed. A code works once.
- Sessions last 8 hours, live in an HttpOnly cookie, and end when staff leave the console or press Sign out.
- Every sign-in attempt is counted before it is checked. After 8 attempts from one network, or 10 for one user ID, in 15 minutes, sign-in is locked for the rest of that period. A successful sign-in gives its attempts back.
- The owner can add staff, reset passwords, reset someone's two-step setup (lost phone) and disable accounts. Disabling takes effect at once, even for people already signed in.
- If the owner loses their phone: set `OWNER_2FA_RESET` in Netlify to a new value and redeploy. The owner sets up two-step again at the next sign-in.
- Only the owner can delete records, export data, search for a person, or manage accounts.

**What staff can see**
- The lists in the console carry no emails, phone numbers or contact names. Those load only when a record is opened, and each time is recorded with the person's user ID. Each person can open at most 120 records an hour.
- Staff decisions cannot overwrite contact details, consent evidence or the reference code.
- The owner's **Recent activity** shows sign-ins, records opened, searches, exports, changes and deletions. Search text is never stored in the log.
- This is a deterrent and an audit trail, not a wall: a staff member who needs to see a record can see it.

**Status checks**
- At submission, each person is shown a reference code (like `AIM-ABCDE-12345`) once. The server keeps only a scrambled form. The status page needs the code and the email, and says the same thing for a wrong code or a wrong email.

**Browser protections** (set in `netlify.toml`): a Content-Security-Policy that only allows this site's own scripts (plus Cloudflare Turnstile if you switch it on), no framing, HSTS, and a restrictive permissions policy.

**Privacy**
- A public **Privacy notice** page, linked from the footer and from every form (`yoursite/#privacy` can be shared).
- Every form has a required consent box. The time and the notice version (now 1.1) are saved with each submission.
- Owner-only **Data & exports** tool for access, correction and deletion requests.

## Backups and exports

- A scheduled function runs every day (about 00:00 UTC) and saves all records to a separate Netlify store, keeping the last 14 days. This protects against accidental deletion and bad edits. It sits in the same Netlify account, so it does not protect against someone who has that account. **Download an export now and then and keep it somewhere StartupTN controls.**
- The owner's **Data & exports** tab downloads everything as JSON, or one list as CSV. Exports contain personal data: store them securely and delete them when done. Every export is logged.
- To restore: `NETLIFY_SITE_ID=... NETLIFY_AUTH_TOKEN=... node scripts/restore.mjs <file.json>`. Records with the same id are replaced. A restore from a **daily backup** also brings back reference codes. A restore from a downloaded **export** does not: those people's status checks stop working. Staff accounts are not in backups; the owner recreates them.
- Deleted records stay in daily backups until those days expire (up to 14 days). The privacy notice says so.

## Before you launch

- **Have the privacy notice reviewed.** I drafted it from what the site actually does and the main points of India's Digital Personal Data Protection Act, 2023. It is not legal advice. Check with StartupTN's legal team, especially: who the notice names as responsible, the retention period, the grievance officer, the 14-day backups, and whether providers or expert validators may see submitted details.
- **Hosting location.** Netlify Blobs stores data with Netlify, which may be outside India. Confirm that this is acceptable for StartupTN. If it is not, the React app can move as is, but the API needs a small server and a database.
- Keep `OWNER_PASSWORD` and `SESSION_SECRET` out of the repository. Changing `SESSION_SECRET` signs everyone out.
- Switch on the Turnstile CAPTCHA if you see spam.
- Have an independent security test done before wide public launch.

## Run locally

```
npm install
cp .env.example .env     # fill in the values
npm run dev              # Netlify Dev at http://localhost:8888
npm test
```

## Not yet tested on a live site

The tests and a full browser run used an in-memory stand-in for Netlify Blobs. These parts depend on the real service and need the smoke test above:

- The atomic counters use Blobs' conditional writes (`@netlify/blobs` 10.0.0, `onlyIfMatch` / `onlyIfNew`). If the first submissions fail or are refused, check the function logs.
- The daily backup only runs on a published production deploy. Check the **Functions** page in Netlify the day after launch to see that it ran.
- Cloudflare Turnstile with real keys.

## Known limits

- Each record is one blob and the console loads them all at once. That suits hundreds of records. Beyond a few thousand, move to a database.
- There is no email-based password reset. The owner resets staff passwords; the owner's own password is changed in Netlify settings.
- Someone who can read your Netlify account or its environment variables can read everything and can reset the owner's two-step setup. Protect that account with its own two-step sign-in.
- Repeated wrong passwords for a user ID lock that user out for the rest of the 15 minutes, so someone could lock a known user ID out on purpose. The owner can still sign in from a different network.
- Staff can still see the contact details of any record they open (see "What staff can see").
