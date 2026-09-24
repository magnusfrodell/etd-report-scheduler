# Changelog

Database migrations run automatically at start-up. Every version runs as a single container
with its state in the `/data` volume.

## 0.7.0 - Partner scale

### Added
- **Schedules for all tenants or a group** - which tenants a schedule covers is worked out when it runs, so tenants added later are included without touching the schedule. Groups come from a new *group* field in the tenant reporting profile.
- **Recipients per tenant** - a *report recipients* field in the reporting profile; a schedule sends to its own recipients, each tenant's, or both. Tenants without recipients are flagged on the Schedules page and get archive-only reports.
- **Only send when there are findings** - for compromise indicators, health check, campaigns, exposure and vendor risk. The report is still generated and archived, and the archive says why it was not sent.
- **+ Schedule** and **Scheduled** links on the report cards; the schedule form opens with the report chosen.
- One alert per schedule run that covers many tenants, listing the tenants that need attention.

### Changed
- **Run now** on a schedule runs it for every tenant it covers.
- Catch-up after an outage completes a schedule tenant by tenant, without running a tenant twice.

### Fixed
- Cron day-of-week numbers were off by one: `1` ran on Tuesday and `7` was rejected, so weekly default schedules arrived a day late. Cron expressions now follow standard cron (0 or 7 = Sunday, 1 = Monday).

### Upgrade notes
- Migration 0007 runs automatically.
- If you entered a day-of-week number to work around the off-by-one, check your schedules.

## 0.6.0 - Operations and data quality

### Added
- **Data quality** page: per tenant and data stream (daily statistics, convicted messages, Log Export, history backfill) the last successful collection, whether it is late or stalled, each collector's own last error, days with statistics, unreadable log files and API requests used today.
- **Alerts** by e-mail to configurable recipients: failed or partly delivered scheduled reports, and stalled data collection - at most once a day per tenant and stream.
- **Backups**: a nightly consistent snapshot of the SQLite database (online backup API) in `DATA_DIR/backups`, `python -m app.manage backup [--with-reports]`, a button in Settings and `RESTORE.txt` in every backup.
- Settings for report archive retention, alert recipients and backups to keep, and a storage overview.
- A start-up check that `ENCRYPTION_KEY` can decrypt the stored credentials, shown to administrators and on `/api/health`.

### Changed
- After an outage longer than the refresh window, daily statistics are collected from the day of the last success.
- API usage is counted with one atomic update, so overlapping collectors no longer lose each other's requests.
- Each collector keeps its own error; a healthy collector no longer clears another one's.
- Archived reports are deleted together with their files after `archive_retention_days`; deleting a tenant deletes its report files; a nightly clean-up removes report files that no run refers to.
- Dependencies are locked with hashes (`requirements.in` -> `requirements.txt`) and the base image is pinned by digest.
- A release tag publishes the image only after the tests, the migration check, `pip-audit` and a container smoke test pass. CI renders every report to PDF. Dependabot proposes updates weekly.

### Fixed
- A wrong `ENCRYPTION_KEY` made every page that reads the settings fail.

## 0.5.3 - Truthful reports and run history

### Fixed
- Deleting a schedule deleted its archived reports; they are now kept.
- Runs interrupted by a restart stayed "running" for ever; they are marked failed at start-up.
- Scheduled reports that fell due while the service was down are generated at start-up - at most three per schedule, only for the outage.
- Recipients refused by the relay were recorded as delivered; they are now reported, and a failed send keeps the generated report.
- Posture score: missing evidence counted as a pass. Missing data is now "unknown", there is no score or grade below 80 % assessable weight, and unremediated retro verdicts count in the dwell time.
- Authentication posture no longer presents a published DMARC policy as proof that messages authenticated.
- Unreadable Log Export lines were dropped silently. They are counted, the file is fetched again and then marked partial, hours at the link limit count as gaps, and the audit report no longer claims proof of completeness.
- The Very Attacked People top-10 share could exceed 100 %.
- Vendor risk missed subdomain spoofs of protected domains.

## 0.5.2 - Security hardening

### Fixed
- Tenant and user names could inject JavaScript into delete confirmations. No inline scripts remain.
- SMTP STARTTLS did not verify the relay. The certificate and host name are now checked, with an optional extra CA and an explicit opt-out.
- Cross-origin form posts were accepted, including from other ports on the same host. They are now refused (Fetch Metadata with an Origin fallback); `TRUSTED_ORIGINS` covers proxies that rewrite `Host`.
- Open redirects after sign-in and tenant selection.

### Added
- Content Security Policy, `nosniff`, same-origin framing and `Cache-Control: no-store`; archived reports are served in a CSP sandbox.
- Throttling of failed sign-ins per account and client.

### Changed
- `FORWARDED_ALLOW_IPS` defaults to `127.0.0.1` instead of trusting every client.
- `python-multipart` 0.0.18 or later.

## 0.5.1 - Report cards and archive

- Reports page with a card per report, grouped by category, with the last run, schedules, Run now and options.
- Archive browser: filters by report, tenant and status, a month timeline, a scaled preview, keyboard navigation and deep links from the dashboard.
- Period labels and times in the configured timezone; wide tables fit A4 in PDFs.

## 0.5.0 - Posture and risk reports, Log Export

- Log Export collector (audit and message events) and per-tenant profiles: own domains, vendors, VIPs and user labels.
- Five reports: authentication posture, audit and compliance, posture and effectiveness (quarterly), techniques and business risk, and vendor risk.
- Quarterly periods.

## 0.4.0 - Message-level reports

- Very Attacked People index with VIP mailboxes, campaign clusters, and exposure and dwell time.

## 0.3.0 - Users and roles

- Local users with global roles (admin, tenant admin, user) and per-tenant roles (viewer, operator, manager), enforced on every request.
- `python -m app.manage` to list users, reset passwords and create users.

## 0.2.0 - History and publishing

- 90 days of history collected within the daily API budget.
- CI and multi-arch images on GHCR.

## 0.1.0 - 0.1.4 - First releases

- Collectors for daily statistics and convicted messages, a scheduler, e-mail delivery, a report archive and four reports: executive summary, compromise indicators, health check and cross-tenant roll-up, followed by fixes.
