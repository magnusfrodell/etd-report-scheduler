# ETD Report Scheduler, scheduled multi-tenant reporting for Cisco Secure Email Threat Defense

Cisco Secure Email Threat Defense (ETD) has good reporting pages but no way to schedule them, no history beyond 90 days, no period-over-period comparison and no view across several tenants. This tool closes those gaps. It runs as a single Docker container inside the customer's or partner's network, collects data from the [ETD public API](https://developer.cisco.com/docs/message-search-api/) every day, stores it locally, and generates and e-mails reports on a schedule.

The application is multi-tenant by construction. Every ETD tenant is a row with its own region, client ID, client secret and API key; a customer with one tenant simply adds one. Partners add many and get a cross-tenant roll-up on top of the per-tenant reports.

What it adds on top of the built-in ETD console:

* **Scheduling and delivery** – cron-based schedules per report and tenant, HTML e-mail with optional PDF attachment, archive of every generated report.
* **History and comparison** – daily statistics are kept as long as you like (retention is configurable, ETD keeps 90 days), so every report compares the period with the previous one.
* **Reports built on message data** – threat-convicted messages are collected through the Message Search API, which enables reports ETD does not offer (compromise indicators on outgoing/internal mail today; techniques, dwell time and campaign clustering are on the roadmap).
* **Cross-tenant view** – ranking, spikes, collector errors and data gaps across all connected tenants.

Bundled reports:

| Report | Scope | Default period | What it contains |
|---|---|---|---|
| Executive summary | per tenant | monthly | Everything on the Trends/Impact Report pages plus period-over-period deltas, a daily series, 1-year projections, top targets and top external threat senders |
| Compromise indicators | per tenant | daily | Threat verdicts on outgoing and internal mail grouped by sender, with recipients, verdicts, first/last seen and remediation state |
| Health check | per tenant | daily | Yesterday's volume against the 30-day baseline (catches broken journaling/connectors), threat spikes, collector errors |
| Cross-tenant roll-up | all tenants | weekly | All tenants ranked by threats with change, threat rate, spikes, errors and missing data |

**Technology stack:** Python 3.12, FastAPI, SQLAlchemy 2 + Alembic (SQLite by default, PostgreSQL optional), APScheduler, Jinja2, WeasyPrint for PDF, httpx for the ETD API. Standalone application, delivered as a Docker image; no external services other than the ETD API and an SMTP relay.

**Status:** 0.2.0, alpha. The collectors, scheduler, four reports and the admin UI work end to end against a fake ETD API in the test-suite (`pytest`, 20 tests) and have been smoke-tested as a running application. Validation against production ETD tenants in all five regions is the next step - please open an issue with what you find. This is community sample code, not a Cisco product, and is not supported by Cisco TAC.

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

Ideas for extending the solution: technique and business-risk breakdowns, dwell time for retrospective verdicts, campaign clustering by subject/URL/attachment hash, audit-log compliance reports through the Log Export API, an OIDC login, webhook delivery to Teams/Slack.

## Installation

### Option A: Docker (recommended)

Prerequisites: Docker 24+ with Compose, network access from the container to `api.<region>.etd.cisco.com` (HTTPS) and to your SMTP relay.

A pre-built multi-arch image (amd64/arm64) is published for every release tag:

```bash
docker pull ghcr.io/magnusfrodell/etd-report-scheduler:0.2.0
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

The image runs as an unprivileged user, exposes port 8080, keeps all state in the `/data` volume and reports its health on `/api/health` (used by the Docker health check). Put a reverse proxy with TLS in front of it and set `COOKIE_SECURE=true`.

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
| `ADMIN_PASSWORD` | yes | – | Password of the built-in admin user |
| `ADMIN_USERNAME` | no | `admin` | Admin user name |
| `DATA_DIR` | no | `/data` in Docker, `./data` otherwise | Database, report archive |
| `DATABASE_URL` | no | SQLite in `DATA_DIR` | e.g. `postgresql+psycopg://user:pass@host/db` (add `psycopg[binary]` to `requirements.txt`) |
| `LOG_LEVEL` | no | `INFO` | Log verbosity (stdout) |
| `HTTP_TIMEOUT` | no | `30` | Seconds per ETD API request |
| `SCHEDULER_ENABLED` | no | `true` | `false` runs the UI without any automatic jobs |
| `SESSION_MAX_AGE_SECONDS` | no | `43200` | Admin session lifetime |
| `COOKIE_SECURE` | no | `false` | Set `true` behind HTTPS |

### In the UI (stored in the database)

* **Tenants** – display name, region (`Beta` for accounts in the ETD beta programme), client ID, client secret and API key. Create these in ETD under *Administration > API Clients* (admin or super-admin role) and *API Key > Generate New Key*; the API key is sent as the `x-api-key` header on every call. The connection is tested when you save; on success the initial collection starts in the background and the *History* column shows the backfill progress (`recent only` → `n of 90 days, backfilling` → `90 days`). *API calls today* shows quota use per tenant.
* **Schedules** – report, tenant (or all tenants for the roll-up), cron expression in the configured timezone, recipients, HTML or PDF. Each report has a sensible default cron.
* **Settings** – timezone (IANA name, e.g. `Europe/Stockholm`), SMTP relay, partner recipients (default for cross-tenant reports), retention in days, which verdicts to store per message (threats only by default: `bec`, `scam`, `phishing`, `malicious`; adding `spam`/`graymail` multiplies the volume), the daily API budget per tenant (default 8 000 of ETD's 10 000) and the backfill window size.

### What runs automatically

| Job | Schedule (configured timezone) | Calls per tenant |
|---|---|---|
| Initial collection when a tenant is added: 90 days of daily statistics, top lists for the previous calendar months, the last 7 days of convictions, then backfill | immediately, in the background | 3 + 2 per month + convictions |
| Daily statistics (Reporting API: directions, verdicts, retroVerdicts, top targets, top threat senders) | 02:15 daily | 5 (+2 when a new month completes) |
| Threat-convicted messages (Message Search API, incremental with a 7-day rescan for retrospective verdicts) | :20 every hour | 1 per 100 messages |
| History backfill (newest-first 7-day windows back to the 90-day horizon, until done) | :40 every hour | 1 per 100 messages, capped by the daily budget |
| Retention purge | 03:30 daily | 0 |
| Report schedules | as configured | 0 (reads the local database only) |

All ETD calls go through a per-tenant rate limiter (2 requests/s, the documented sustained limit) shared by every job, so parallel jobs for the same tenant never trigger 429s. A tenant with 2 000 threats a month backfills 90 days in about 60 requests; one with 50 000 a month needs about 1 500 - still a fraction of the quota, but the budget makes the worst case safe.

A tenant that fails does not stop the others; the error is shown on the Tenants page and in the health-check report.

## Usage

Sign in, add a tenant, test the connection and start a collection:

1. **Tenants > Add tenant** – name, region, client ID, client secret, API key. Click **Test connection**, then **Collect now**.
2. **Settings** – set your timezone and SMTP relay, send a test e-mail.
3. **Schedules > Add schedule** – pick a report and tenant, leave the cron blank to use the default, add recipients. **Run now** generates and sends it immediately.
4. **Report archive** – one **Run now** per report: pick the period, optionally recipients (empty = archive only), and the tenant from the header switcher ("All tenants" runs a per-tenant report for every enabled tenant). Below it, every run with status, period, delivery and links to the HTML/PDF.

The tenant switcher in the header filters the dashboard, schedules and archive to one tenant, or shows all.

The same actions are available as JSON for automation (session cookie required, interactive documentation at `/api/docs`):

```bash
# health (no authentication)
curl http://localhost:8080/api/health

# sign in and keep the cookie
curl -c cookies.txt -d "username=admin&password=<ADMIN_PASSWORD>" http://localhost:8080/login

# list tenants, start a collection, generate a report
curl -b cookies.txt http://localhost:8080/api/tenants
curl -b cookies.txt -X POST http://localhost:8080/api/tenants/1/collect
curl -b cookies.txt -X POST "http://localhost:8080/api/reports/executive_summary/run?tenant_id=1&deliver=false"
```

Generated files are stored under `/data/reports/<tenant>/<report>/<timestamp>-run<id>.html|pdf` in the volume; the run id keeps every run's files distinct.

## Additional paragraphs

### Continuous integration

`.github/workflows/ci.yml` runs ruff, the test-suite and an Alembic consistency check on every push and pull request. `.github/workflows/docker.yml` builds and publishes the container image to GitHub Container Registry when a `v*` tag is pushed:

```bash
git tag v0.2.0 && git push origin v0.2.0
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
  COL -->|"/v1/messages/report, /report/top, /search"| ETD[(ETD API<br/>api.us / de / au / in / ae / beta)]
  DEL --> SMTP[SMTP relay]
```

Tenant isolation is enforced in one place: every query helper in `app/reports/repo.py` takes `tenant_id` as a required argument, and only the cross-tenant roll-up uses the `*_all_tenants` functions. Adding a report means one Python module, one template and one registry entry, see [CONTRIBUTING](./CONTRIBUTING.md).

### ETD API notes that shaped the code

* Regional endpoints: `api.us|de|au|in|ae.etd.cisco.com`; a tenant in the Europe data centre must use `de`. Accounts in the ETD beta programme use `api.beta.etd.cisco.com`, selectable as region *Beta*.
* Token: `POST /v1/oauth/token` with HTTP basic auth (client ID/secret) and the `x-api-key` header; the JWT lives 60 minutes and is cached per tenant.
* Rate limit per tenant: 2 requests/s, burst 4, 10 000 per day. Daily collection uses well under 100.
* Reporting API reaches 90 days back with `aggregationInterval` 1h/1d/30d; Message Search accepts 32-day windows with 100 messages per page; Log Export (not used yet) serves 3-hour windows with 30-day retention.
* Statistics are aggregated on UTC days. Reports label periods in your timezone but sum UTC days, exactly like the week/month charts in the ETD console.

## Known issues

* Not yet validated against production ETD tenants; the fake API in `tests/etd_mock.py` follows the DevNet documentation and Cisco's own Sentinel connector.
* The Reporting API's top-sender list contains external senders only; internal threat senders come from the compromise-indicators report instead.
* Retrospective verdicts on messages older than the rescan window (7 days by default) are not picked up; increase `convictions_rescan_days` in Settings if you need more.
* Backfill covers threat verdicts only (the stored verdict set). Backfilling spam and graymail for 90 days would run into the daily quota on any sizeable tenant, so those are collected from the day they are enabled.
* One admin account only. Put the UI behind your reverse proxy's authentication if you need more, or contribute OIDC support.
* PDF rendering requires WeasyPrint's system libraries (present in the Docker image). Without them, reports are sent as HTML.

Please use [GitHub Issues](../../issues) for bugs and feature requests; include the ETD region, the report key and the relevant lines from the container log (`docker compose logs`).

## Getting help

Open an issue in this repository. For questions about the ETD API itself, see the [DevNet documentation](https://developer.cisco.com/docs/message-search-api/) and the [ETD user guide](https://docs.cmd.cisco.com/en/Content/secure-email-threat-defense-user-guide/homeUG.htm). Cisco TAC does not support this code.

## Getting involved

Contributions are welcome, particularly:

* Reports from the roadmap (techniques/business risk, dwell time, campaign clustering, audit compliance via Log Export).
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
