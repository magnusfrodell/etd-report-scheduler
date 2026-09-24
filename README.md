# ETD Report Scheduler, scheduled multi-tenant reporting for Cisco Secure Email Threat Defense

Cisco Secure Email Threat Defense (ETD) has good reporting pages but no way to schedule them, no history beyond 90 days, no period-over-period comparison and no view across several tenants. This tool closes those gaps. It runs as a single Docker container inside the customer's or partner's network, collects data from the [ETD public API](https://developer.cisco.com/docs/message-search-api/) every day, stores it locally, and generates and e-mails reports on a schedule.

The application is multi-tenant by construction. Every ETD tenant is a row with its own region, client ID, client secret and API key; a customer with one tenant simply adds one. Partners add many and get a cross-tenant roll-up on top of the per-tenant reports.

What it adds on top of the built-in ETD console:

* **Scheduling and delivery** – cron-based schedules per report and tenant, HTML e-mail with optional PDF attachment, archive of every generated report.
* **History and comparison** – daily statistics are kept as long as you like (retention is configurable, ETD keeps 90 days), so every report compares the period with the previous one.
* **Reports built on message data** – threat-convicted messages are collected through the Message Search API, which enables reports ETD does not offer: compromise indicators on outgoing/internal mail, a Very Attacked People index, campaign clustering and dwell-time/exposure analysis.
* **Posture, risk and compliance** – with ETD's Log Export and DNS: authentication posture of own domains, vendor and look-alike risk, technique and attachment trends, an audit trail kept beyond ETD's 30 days, and a quarterly posture score for management.
* **Cross-tenant view** – ranking, spikes, collector errors and data gaps across all connected tenants.
* **Users and roles** – global roles (admin, tenant admin, user) plus per-tenant roles (viewer, operator, manager), so a partner can give each customer's people access to exactly their tenant and nothing else.

Bundled reports:

| Report | Scope | Default period | What it contains |
|---|---|---|---|
| Executive summary | per tenant | monthly | Everything on the Trends/Impact Report pages plus period-over-period deltas, a daily series, 1-year projections, top targets and top external threat senders |
| Compromise indicators | per tenant | daily | Threat verdicts on outgoing and internal mail grouped by sender, with recipients, verdicts, first/last seen and remediation state |
| Health check | per tenant | daily | Yesterday's volume against the 30-day baseline (catches broken journaling/connectors), threat spikes, collector errors |
| Very Attacked People | per tenant | monthly | Attack index (0–1000) per mailbox from verdict weight, technique severity, impersonation, retro delivery, missing remediation and targeting; VIP flags, rank movement, attack concentration |
| Campaign clusters | per tenant | daily | Threats grouped into campaigns by normalised subject + sender domain, URL host and attachment hash; reach, remediation state, samples, what is still in inboxes |
| Exposure and dwell time | per tenant | weekly | Time retro-convicted messages spent in inboxes until verdict and remediation (median/p90/max, buckets, per verdict), every unremediated threat with age, auto vs manual remediation |
| Techniques and business risk | per tenant | weekly | ETD detection techniques grouped into families (impersonation, social engineering, link, attachment, evasion, sender reputation, known relationship), business risk, QR-code threats, text-only lures that look like callback phishing, attachment types incl. HTML/SVG smuggling and double extensions, abused legitimate services (SharePoint, Cloudflare Pages, shorteners ...) - with gateway and awareness recommendations |
| Vendor risk | per tenant | weekly | Possibly compromised suppliers and partners (threats from listed vendors, from domains with a history of clean mail, or that ETD tags as frequent senders), look-alike domains of own domains, vendors and counterparties (TLD swap, homoglyph, typosquat, combosquat, subdomain spoof) - including look-alikes that were delivered, new or rare senders with BEC/scam lures, vendor inventory |
| Authentication posture | per tenant | monthly | SPF, DMARC, MTA-STS, TLS-RPT and BIMI for own domains from DNS, spoofing of own domains, Return-Path/Reply-To alignment across all incoming mail, and the DMARC policies of the domains that sent threats |
| Audit and compliance | per tenant | monthly | Who did what in ETD (API clients, policy and configuration, users, sign-ins), reclassifications and remediations per analyst with false-positive/negative proxies, failed actions, and how completely the audit log was collected (unreadable log lines are counted, not dropped) - kept beyond ETD's 30 days |
| Posture and effectiveness | per tenant | quarterly | One page for management: posture score from weighted checks, effectiveness KPIs, six-month trend, prioritised gaps and the threat landscape in brief; no score or grade is given when too little of the data is available |
| Cross-tenant roll-up | all tenants | weekly | All tenants ranked by threats with change, threat rate, spikes, errors and missing data |

**Technology stack:** Python 3.12, FastAPI, SQLAlchemy 2 + Alembic (SQLite by default, PostgreSQL optional), APScheduler, Jinja2, WeasyPrint for PDF, httpx for the ETD API. Standalone application, delivered as a Docker image; no external services other than the ETD API and an SMTP relay.

**Status:** 0.6.0, alpha. The collectors (including Log Export), scheduler, twelve reports and the admin UI work end to end against a fake ETD API in the test-suite (`pytest`, 96 tests) and have been smoke-tested as a running application. Validation against production ETD tenants in all five regions is the next step - please open an issue with what you find. This is community sample code, not a Cisco product, and is not supported by Cisco TAC.

<!-- Add a screenshot of the dashboard here once you run it against a real tenant: ![Dashboard](docs/dashboard.png) -->

# Use Case

A security team or a managed service provider wants the numbers ETD shows in its console delivered automatically: a monthly summary to management, a daily heads-up when an internal account starts sending threats, and for partners one overview of every customer tenant. ETD provides the data through its Reporting, Message Search and Log Export APIs but has no scheduler and no cross-tenant view.

With this code you can:

- Connect any number of ETD tenants (Americas, Europe, Australia, India, UAE, plus the beta environment for beta accounts) with credentials encrypted at rest.
- Collect daily statistics with five API calls per tenant and day, and threat-convicted messages incrementally, staying far inside ETD's quota of 10 000 requests per tenant and day.
- Get the full 90 days ETD keeps as soon as a tenant is added: statistics for all 90 days (three calls), top lists for the previous calendar months, and convictions backfilled newest-first in 7-day windows, throttled to 2 requests/s and capped by a daily API budget that resumes the next day.
- Schedule reports with cron expressions in your own timezone, e-mail them as HTML and PDF, and keep an archive.
- Build long-term trend reports: the tool stores what ETD forgets after 90 days.
- Run a weekly roll-up over all tenants with spike and error detection - the report a partner SOC actually reads.

Challenges solved along the way: ETD's API only exposes UTC days and 32-day search windows (the client chunks and clamps automatically), the DevNet documentation is inconsistent about `aggregateBy` (`directions` vs `direction` - the client tries both and remembers what works), retrospective verdicts change yesterday's numbers (trailing days are re-collected every run), and SQLite drops timezone information (a custom column type keeps every datetime UTC-aware).

Ideas for extending the solution: "caught behind the gateway" with SMA cross-referencing, user-reported-vs-verdict, department enrichment from Entra ID for the VAP index, DKIM selector discovery, an OIDC login, webhook delivery to Teams/Slack.

## Installation

### Option A: Docker (recommended)

Prerequisites: Docker 24+ with Compose, network access from the container to `api.<region>.etd.cisco.com` (HTTPS) and to your SMTP relay.

A pre-built multi-arch image (amd64/arm64) is published for every release tag:

```bash
docker pull ghcr.io/magnusfrodell/etd-report-scheduler:0.6.0
```

To use it, set `image:` instead of `build:` in `docker-compose.yml` (the line is there, commented out). To build yourself instead:

Clone the repo
```bash
git clone https://github.com/magnusfrodell/etd-report-scheduler.git
```
Go to your project folder
```bash
cd etd-report-scheduler
```
Create the environment file and generate the three required secrets
```bash
cp .env.example .env
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))"
python3 -c "from cryptography.fernet import Fernet; print('ENCRYPTION_KEY=' + Fernet.generate_key().decode())"
```
Paste the two values into `.env` and set `ADMIN_PASSWORD`. Back up `ENCRYPTION_KEY` together with the data volume: without it the stored tenant credentials cannot be decrypted.

Build and start
```bash
docker compose up -d --build
```
Open http://localhost:8080 and sign in as `admin` with the password from `.env`.

Without Compose:
```bash
docker build -t etd-report-scheduler .
docker run -d --name etd-reports --env-file .env -p 8080:8080 -v etd-data:/data etd-report-scheduler
```

The image runs as an unprivileged user, exposes port 8080, keeps all state in the `/data` volume and reports its health on `/api/health` (used by the Docker health check). Put a reverse proxy with TLS in front of it, set `COOKIE_SECURE=true` and set `FORWARDED_ALLOW_IPS` to the proxy's address so client addresses and HTTPS are taken from its `X-Forwarded-*` headers (by default no proxy is trusted).

### Option B: Python virtual environment (development)

Prerequisites: Python 3.11 or newer. On macOS and Linux, WeasyPrint needs Pango (`brew install pango` / `apt install libpango-1.0-0 libpangoft2-1.0-0`); without it reports are delivered as HTML only. On Windows, install WeasyPrint's GTK dependencies as described in the [WeasyPrint documentation](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html) or skip PDF.

Set up a Python venv
```bash
python3 -m venv venv
```
Activate your venv
```bash
source venv/bin/activate        # Windows: venv\Scripts\activate
```
Install dependencies
```bash
pip install --require-hashes -r requirements.txt
pip install -r requirements-dev.txt
```
Create `.env` as in option A (the default `DATA_DIR` is `./data` outside Docker), then run the tests
```bash
pytest
```

## Configuration

### Environment variables (`.env`)

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `SECRET_KEY` | yes | – | Signs the admin session cookie |
| `ENCRYPTION_KEY` | yes | – | Fernet key; encrypts tenant credentials and the SMTP password in the database |
| `ADMIN_PASSWORD` | yes | – | Password of the first admin user, created when the user table is empty (bootstrap only; afterwards users are managed in the UI) |
| `ADMIN_USERNAME` | no | `admin` | Username of that first admin |
| `DATA_DIR` | no | `/data` in Docker, `./data` otherwise | Database, report archive |
| `DATABASE_URL` | no | SQLite in `DATA_DIR` | e.g. `postgresql+psycopg://user:pass@host/db` (add `psycopg[binary]` to `requirements.in` and regenerate `requirements.txt`, see CONTRIBUTING) |
| `LOG_LEVEL` | no | `INFO` | Log verbosity (stdout) |
| `HTTP_TIMEOUT` | no | `30` | Seconds per ETD API request |
| `SCHEDULER_ENABLED` | no | `true` | `false` runs the UI without any automatic jobs |
| `SESSION_MAX_AGE_SECONDS` | no | `43200` | Admin session lifetime |
| `COOKIE_SECURE` | no | `false` | Set `true` behind HTTPS |
| `FORWARDED_ALLOW_IPS` | no | `127.0.0.1` | Proxies whose `X-Forwarded-*` headers are trusted (comma-separated addresses or networks) |
| `TRUSTED_ORIGINS` | no | – | Extra origins allowed to submit forms, e.g. `https://reports.example.com` behind a proxy that rewrites the `Host` header |

### In the UI (stored in the database)

* **Tenants** – display name, region (`Beta` for accounts in the ETD beta programme), client ID, client secret and API key. Create these in ETD under *Administration > API Clients* (admin or super-admin role) and *API Key > Generate New Key*; the API key is sent as the `x-api-key` header on every call. The connection is tested when you save; on success the initial collection starts in the background and the *History* column shows the backfill progress (`recent only` → `n of 90 days, backfilling` → `90 days`). *API calls today* shows quota use per tenant.
* **Schedules** – report, tenant (or all tenants for the roll-up), cron expression in the configured timezone, recipients, HTML or PDF. Each report has a sensible default cron.
* **Reporting profile per tenant** (Tenants page, manager role) – own domains (blank = detected from outgoing mail and recipients), vendor and partner domains to watch, VIP mailboxes (added to the global list) and names for ETD user ids, because ETD's audit log records users by UUID only.
* **Settings** – timezone (IANA name, e.g. `Europe/Stockholm`), SMTP relay, partner recipients (default for cross-tenant reports), retention in days, which verdicts to store per message (threats only by default: `bec`, `scam`, `phishing`, `malicious`; adding `spam`/`graymail` multiplies the volume), the daily API budget per tenant (default 8 000 of ETD's 10 000), the backfill window size, the global VIP mailboxes, Log Export collection on/off and how long the audit trail is kept (default 730 days).

### Log Export (audit trail, verdict changes, sender history)

Four reports get their full value from ETD's Log Export API. Enable it once per tenant in ETD under *Administration > Business > Export Log Preferences* (tick the audit and message logs); export starts 15-20 minutes later and there is no history from before that. The collector then:

* pulls the last 30 days on the first run and every hour after that, in 3-hour windows (the API maximum), re-requesting the last six hours because new files keep arriving;
* downloads the files from their pre-signed S3 links with a plain GET - the ETD credentials are never sent to S3 - and deduplicates them by path, so re-runs never double count;
* stores every audit event (who, IP, user agent, action, status) for `audit_retention_days`, every reclassification and remediation, and a per-day, per-sender-domain summary of *all* mail (volume, convictions, Return-Path and Reply-To misalignment) - not the messages themselves;
* records gaps if it was stopped for longer than ETD's 30-day retention, so the audit report can prove completeness.

The *Log export* column on the Tenants page shows the state (`collecting`, `catching up`, `no data` - usually meaning export is not enabled in ETD - or `error`). ETD's logs contain no SPF/DKIM/DMARC results; the authentication posture report reads those from DNS instead, so the container needs outbound DNS (UDP/TCP 53) to your resolver.

### Users and roles

Two levels of roles. The global role is set per user on the *Users* page (admins only); per-tenant roles are granted on the *Tenants* page by anyone who is a manager of that tenant.

| Global role | Can |
|---|---|
| `admin` | Everything: users, settings, all tenants, cross-tenant reports |
| `tenant_admin` | Create, edit and delete any tenant, all schedules and reports, the cross-tenant roll-up - but not users or settings |
| `user` | Only what is granted per tenant |

| Tenant role | Can |
|---|---|
| `viewer` | Dashboard and report archive for the tenant, download reports |
| `operator` | viewer + Run now, schedules, Collect now, Test connection |
| `manager` | operator + edit credentials, enable/disable, delete the tenant, grant and revoke access for other users |

Admins and tenant admins implicitly hold `manager` on every tenant. The tenant switcher in the header only lists tenants the user can see, "All tenants" runs per-tenant reports only for tenants the user operates, and every handler enforces the role server-side - the UI merely hides what is not allowed. Passwords are stored as scrypt hashes; changing or resetting a password signs out that user's other sessions.

Locked out? Reset a password (or create an admin) from inside the container:

```bash
docker exec etd-report-scheduler python -m app.manage list-users
docker exec etd-report-scheduler python -m app.manage reset-password admin 'NewSecret123'
docker exec etd-report-scheduler python -m app.manage create-user ops --role tenant_admin --password 'Secret123'
```

### What runs automatically

| Job | Schedule (configured timezone) | Calls per tenant |
|---|---|---|
| Initial collection when a tenant is added: 90 days of daily statistics, top lists for the previous calendar months, the last 7 days of convictions, backfill, then 30 days of Log Export | immediately, in the background | 3 + 2 per month + convictions + 240 |
| Daily statistics (Reporting API: directions, verdicts, retroVerdicts, top targets, top threat senders) | 02:15 daily | 5 (+2 when a new month completes) |
| Threat-convicted messages (Message Search API, incremental with a 7-day rescan for retrospective verdicts) | :20 every hour | 1 per 100 messages |
| History backfill (newest-first 7-day windows back to the 90-day horizon, until done) | :40 every hour | 1 per 100 messages, capped by the daily budget |
| Log Export (audit and message logs; 30 days on the first run, then the last hours) | :50 every hour | 1 per 3-hour window (~3 per hour, 240 on the first run) |
| Retention purge | 03:30 daily | 0 |
| Report schedules | as configured | 0 (reads the local database only) |

All ETD calls go through a per-tenant rate limiter (2 requests/s, the documented sustained limit) shared by every job, so parallel jobs for the same tenant never trigger 429s. A tenant with 2 000 threats a month backfills 90 days in about 60 requests; one with 50 000 a month needs about 1 500 - still a fraction of the quota, but the budget makes the worst case safe.

A tenant that fails does not stop the others; the error is shown on the Tenants page and in the health-check report.

## Usage

Sign in as the bootstrap admin, add a tenant, then add users:

1. **Tenants > Add tenant** – name, region, client ID, client secret, API key. The connection is tested on save and the 90-day history collection starts in the background.
1. **Users > Add user** – username, role and an initial password; then open the tenant's *Edit credentials and access* section on the Tenants page and grant viewer, operator or manager.
2. **Settings** – set your timezone and SMTP relay, send a test e-mail. The relay's certificate is verified; for a relay with an internal CA, paste the CA certificate in the e-mail settings.
3. **Schedules > Add schedule** – pick a report and tenant, leave the cron blank to use the default, add recipients. **Run now** generates and sends it immediately.
4. **Reports** – one card per report, grouped into *Overview*, *Threats*, *Exposure and risk* and *Operations and compliance*. Each card shows the default period, whether it is scheduled, the latest run and how many runs are archived. **Run now** generates it for the tenant in the header switcher ("All tenants" runs a per-tenant report for every enabled tenant you operate); **Options** picks another period, recipients (empty = archive only) and the format.
5. **Archive** – every generated report, filtered by report, tenant and status and grouped by month. The selected report is previewed next to the list (scaled to fit), with **Open** for full size and **PDF** to download; step through runs with ↑/↓ or j/k. Failed runs show their error, and an empty filter offers **Run now** for that report and tenant. Links in the dashboard's recent runs open the run here. Each run shows whether it came from a schedule, was run manually or via the API, or was caught up after downtime, and which recipients the relay refused. Deleting a schedule keeps its archived reports.
6. **Data quality** – per tenant and data stream (daily statistics, convicted messages, Log Export, history backfill): the last successful collection, whether it is late or stalled, each collector's own last error, days with statistics, unreadable log files and API requests used today, with **Collect now**.
7. **Settings > E-mail > Alert recipients** – e-mailed when a scheduled report fails or is only partly delivered, and once a day while a data stream is stalled. **Settings > Storage and backups** shows the archive and database size, the newest backups and a **Back up the database now** button.

The tenant switcher in the header filters the dashboard, schedules and report cards to one tenant, or shows all; the archive starts from it and has its own tenant filter. Times in the archive are shown in the timezone from Settings.

The same actions are available as JSON for automation (session cookie required, interactive documentation at `/api/docs`):

```bash
# health (no authentication)
curl http://localhost:8080/api/health

# sign in and keep the cookie
curl -c cookies.txt -d "username=admin&password=<ADMIN_PASSWORD>" http://localhost:8080/login

# who am I and which tenants can I see; list tenants, start a collection, generate a report
curl -b cookies.txt http://localhost:8080/api/me
curl -b cookies.txt http://localhost:8080/api/tenants
curl -b cookies.txt -X POST http://localhost:8080/api/tenants/1/collect
curl -b cookies.txt -X POST "http://localhost:8080/api/reports/executive_summary/run?tenant_id=1&deliver=false"
```

Generated files are stored under `/data/reports/<tenant>/<report>/<timestamp>-run<id>.html|pdf` in the volume; the run id keeps every run's files distinct.

## Additional paragraphs

### Continuous integration

`.github/workflows/ci.yml` runs ruff, the test-suite and an Alembic consistency check on every push and pull request. `.github/workflows/docker.yml` builds and publishes the container image to GitHub Container Registry when a `v*` tag is pushed:

```bash
git tag v0.6.0 && git push origin v0.6.0
```

### Architecture

```mermaid
flowchart LR
  subgraph container["Docker container"]
    UI[FastAPI admin UI + JSON API]
    SCH[APScheduler]
    COL[Collectors]
    REP[Report builders]
    DEL[Delivery: archive, PDF, SMTP]
    DB[(SQLite / PostgreSQL<br/>tenant_id on every row)]
    UI --> DB
    SCH --> COL --> DB
    SCH --> REP --> DB
    REP --> DEL
  end
  COL -->|"/v1/messages/report, /report/top, /search, /logs/downloadLinks"| ETD[(ETD API<br/>api.us / de / au / in / ae / beta)]
  COL -->|"pre-signed GET, no credentials"| S3[(Log Export files)]
  REP -->|"TXT: SPF, DMARC, MTA-STS, TLS-RPT, BIMI"| DNS[DNS resolver]
  DEL --> SMTP[SMTP relay]
```

Tenant isolation is enforced in one place: every query helper in `app/reports/repo.py` takes `tenant_id` as a required argument, and only the cross-tenant roll-up uses the `*_all_tenants` functions. Adding a report means one Python module, one template and one registry entry, see [CONTRIBUTING](./CONTRIBUTING.md).

### ETD API notes that shaped the code

* Regional endpoints: `api.us|de|au|in|ae.etd.cisco.com`; a tenant in the Europe data centre must use `de`. Accounts in the ETD beta programme use `api.beta.etd.cisco.com`, selectable as region *Beta*.
* Token: `POST /v1/oauth/token` with HTTP basic auth (client ID/secret) and the `x-api-key` header; the JWT lives 60 minutes and is cached per tenant.
* Rate limit per tenant: 2 requests/s, burst 4, 10 000 per day. Daily collection uses well under 100.
* Reporting API reaches 90 days back with `aggregationInterval` 1h/1d/30d; Message Search accepts 32-day windows with 100 messages per page; Log Export serves 3-hour windows with 30-day retention and at most 200 links per response (the collector then re-requests per hour); links are pre-signed S3 URLs valid for one hour. Message events are `create` (every message, verdict and action only when convicted) or `update` (reclassification, remediation); audit events carry category, action, status, user id, IP and user agent. Neither contains SPF/DKIM/DMARC results.
* Statistics are aggregated on UTC days. Reports label periods in your timezone but sum UTC days, exactly like the week/month charts in the ETD console.

### Restarts and outages

- **Interrupted runs** – reports that were being generated when the service stopped are marked failed at start-up instead of staying "running".
- **Missed schedules** – the service writes a heartbeat to the data volume every five minutes. At start-up, scheduled reports that fell due while it was down are generated for the periods they would have covered: at most three per schedule, only for the time the service was down, and only if that period has no run yet.
- **One instance** – start-up recovery and the scheduler assume a single process per data volume; do not run replicas.

- **Statistics gaps** – after an outage longer than the three-day refresh window, the next collection starts from the day of the last success, as far back as the Reporting API keeps history (90 days).

### Backup and restore

- **Nightly** – at 03:45 a consistent snapshot of the database (SQLite's online backup API) is written to `DATA_DIR/backups/etd-backup-<time>.tar.gz`; the newest seven are kept (Settings, 0 = off).
- **On demand** – `docker exec etd-report-scheduler python -m app.manage backup` for the database, `--with-reports` to include the report archive, `--dest` for another folder.
- **Keys** – backups do not contain `ENCRYPTION_KEY` or `SECRET_KEY`. Keep them with your container configuration: without the original `ENCRYPTION_KEY` the tenant credentials in a backup cannot be decrypted. A wrong key is reported at start-up, on `/api/health` and to administrators in the UI instead of failing silently.
- **Restore** – stop the container, replace `DATA_DIR/etd.db` with `etd.db` from the backup (delete `etd.db-wal` and `etd.db-shm`), restore `reports/` if it was included, make the files owned by uid 10001 and start with the same keys. Each backup contains these steps in `RESTORE.txt`.
- **Retention** – archived reports are deleted, rows and files, after `archive_retention_days` (400 by default). Deleting a tenant deletes its report files too, and a nightly clean-up removes report files that no run refers to.

### Security

- **Sign-in** – scrypt password hashes and signed session cookies bound to the password, so changing it signs out every session. Failed sign-ins are throttled per account and client (5 per 15 minutes) and per client (20), which slows guessing without letting anyone lock a user out from elsewhere.
- **Cross-site requests** – anything that changes state must come from the application's own origin. Browsers state this in `Sec-Fetch-Site`, so another web application on the same host but a different port is refused even though it counts as the same site for cookies. Behind a proxy that rewrites the `Host` header, add the public origin to `TRUSTED_ORIGINS`.
- **Browser policy** – a Content Security Policy with no inline scripts, `nosniff`, same-origin framing only and `Cache-Control: no-store` on everything except static assets. Archived reports are served in a CSP sandbox, so text taken from e-mails can never run as the application.
- **E-mail** – STARTTLS verifies the relay's certificate and host name. Turning verification off is possible but shown as a warning in Settings. Implicit TLS on port 465 is not supported; use STARTTLS on 587.
- **Secrets** – tenant credentials and the SMTP password are encrypted with `ENCRYPTION_KEY` (Fernet).

## Known issues

* Not yet validated against production ETD tenants; the fake API in `tests/etd_mock.py` follows the DevNet documentation and Cisco's own Sentinel connector.
* The Reporting API's top-sender list contains external senders only; internal threat senders come from the compromise-indicators report instead.
* Retrospective verdicts on messages older than the rescan window (7 days by default) are not picked up; increase `convictions_rescan_days` in Settings if you need more.
* Backfill covers threat verdicts only (the stored verdict set). Backfilling spam and graymail for 90 days would run into the daily quota on any sizeable tenant, so those are collected from the day they are enabled.
* Local accounts only (no OIDC/SAML yet) - contributions welcome. Put the UI behind your reverse proxy's authentication if your policy requires SSO.
* PDF rendering requires WeasyPrint's system libraries (present in the Docker image). Without them, reports are sent as HTML.
* ETD's audit log identifies users by UUID only; name them in the tenant's reporting profile to get readable audit reports.
* Look-alike detection, text-only "callback" lures and the audit event grouping are heuristics built on ETD's documented technique names and log samples; verify before blocking a domain. QR detection relies on the "QR code" technique and QR flags in `urlMetadata`, whose exact field names are not documented yet.
* DNS posture is read from the container's resolver (cached for a day); DKIM is not checked because selectors cannot be discovered from DNS.

Please use [GitHub Issues](../../issues) for bugs and feature requests; include the ETD region, the report key and the relevant lines from the container log (`docker compose logs`).

## Getting help

Open an issue in this repository. For questions about the ETD API itself, see the [DevNet documentation](https://developer.cisco.com/docs/message-search-api/) and the [ETD user guide](https://docs.cmd.cisco.com/en/Content/secure-email-threat-defense-user-guide/homeUG.htm). Cisco TAC does not support this code.

## Getting involved

Contributions are welcome, particularly:

* Reports from the roadmap (vendor risk, gateway cross-referencing, allow-list risk, user-reported loop, audit compliance and authentication posture via Log Export).
* Feedback from real tenants: field names that differ from the documentation, rate-limit behaviour, regional quirks.
* OIDC login and webhook delivery.

See [CONTRIBUTING](./CONTRIBUTING.md) for the development setup, how to add a report and how to create schema migrations.

## Credits and references

1. [Secure Email Threat Defense API on Cisco DevNet](https://developer.cisco.com/docs/message-search-api/) - authentication, Reporting, Message Search and Log Export API reference.
2. [Cisco Secure Email Threat Defense user guide](https://docs.cmd.cisco.com/en/Content/secure-email-threat-defense-user-guide/homeUG.htm) - the built-in Trends and Impact Report pages this tool complements.
3. [Cisco Email Security - Microsoft Sentinel connector](https://github.com/Cisco-Email-Security/MS_Sentinel_ETD_Connector) - reference for the token response and Message Search pagination.
4. [CiscoDevNet code-exchange-repo-template](https://github.com/CiscoDevNet/code-exchange-repo-template) - README structure.

## Licensing info

This code is licensed under the Cisco Sample Code License, Version 1.1. See [LICENSE](./LICENSE) for details.
