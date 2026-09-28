# Security

ETD Report Scheduler holds API credentials for your Email Threat Defense tenants and the reports built from them, so security problems matter.

## Reporting a vulnerability

Please do not open a public issue. Report it privately through **Security › Report a vulnerability** on this repository's GitHub page, with what you found, how to reproduce it and the version (`/api/health` shows it). You will get an answer within a week, and a fix in a new release as soon as it is ready; you are credited in the release notes unless you prefer otherwise.

This is community sample code, not a Cisco product: vulnerabilities in the tool itself go here, not to Cisco PSIRT. Vulnerabilities in Cisco Secure Email Threat Defense or its API go to [Cisco PSIRT](https://sec.cloudapps.cisco.com/security/center/resources/security_vulnerability_policy.html).

## Supported versions

The latest 1.x release receives security fixes. Upgrade by pulling the new image; database migrations run on start-up.

## How the tool protects what it holds

* Tenant credentials, the SMTP password, the Webex bot token, the single sign-on client secret and chat channel addresses are encrypted in the database (`ENCRYPTION_KEY`); passwords are hashed with scrypt, API keys and session tokens are stored as hashes only.
* Sessions live on the server and end at sign-out, after inactivity, and when a password is changed or an account is disabled.
* Cross-site state changes are refused, a strict Content Security Policy applies, and archived reports are shown sandboxed.
* The activity log records every change, sign-in and opened report - without passwords, tokens or webhook addresses.
