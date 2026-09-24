# Contributing

Thanks for taking the time to contribute. This is a community sample - issues and
pull requests are welcome, TAC cases are not (the code is not a Cisco product).

## Development setup

```bash
git clone https://github.com/magnusfrodell/etd-report-scheduler.git
cd etd-report-scheduler
python3 -m venv venv && source venv/bin/activate
pip install --require-hashes -r requirements.txt   # the locked runtime, as in the image
pip install -r requirements-dev.txt
cp .env.example .env            # fill in SECRET_KEY, ENCRYPTION_KEY, ADMIN_PASSWORD
pytest                          # 115 tests, fake ETD API and fake DNS, no network needed
uvicorn app.main:app --reload --port 8080
```

## Adding a report

1. Create `app/reports/<key>.py` with a `build(session, ctx) -> dict` function.
   Use the helpers in `app/reports/repo.py`; every query takes `tenant_id`.
2. Create `app/templates/reports/<key>.html` extending `email/base_report.html`.
3. Register it in `app/reports/registry.py` (scope `tenant` or `all`, period kind,
   default cron, subject line).
4. Add a test in `tests/test_reports.py` that builds it for two tenants and proves
   the numbers do not leak between them.

## Schema changes

Edit `app/models.py`, then:

```bash
DATABASE_URL=sqlite:///./data/etd.db alembic revision --autogenerate -m "describe change"
alembic check   # must report "No new upgrade operations detected."
```

Migrations run automatically when the container starts.

## Pull requests

* Keep the Cisco Sample Code License header on every source file.
* Run `ruff check .` and `pytest` before opening the PR.
* Describe the ETD API behaviour you relied on and link the DevNet page.

## Dependencies

`requirements.in` lists the direct dependencies with the versions they need. `requirements.txt`
is generated from it with exact versions and hashes for every platform, and it is what the image
and CI install. To add or upgrade a dependency, edit `requirements.in`, regenerate and commit both:

```bash
pip install pip-tools
pip-compile --generate-hashes --allow-unsafe --strip-extras --output-file=requirements.txt requirements.in
```

Dependabot proposes weekly updates for Python packages, GitHub Actions and the pinned base image.
A release tag builds the image only after the tests, the migration check, `pip-audit` on the locked
dependencies and a container smoke test have passed.

## Releasing

1. Bump the version in `app/__init__.py`, `pyproject.toml`, `docker-compose.yml` and `README.md`, and add a section to `CHANGELOG.md`.
2. Commit and push `main` - CI runs on every push.
3. Tag the release; the tag starts the Docker workflow (tests, migration check, `pip-audit`, container smoke test, then the multi-arch image on GHCR):

   ```bash
   git tag -a vX.Y.Z -m "ETD Report Scheduler X.Y.Z"
   git push origin vX.Y.Z
   gh run watch "$(gh run list --workflow=docker.yml --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
   ```

4. When the workflow is green, publish the release notes:

   ```bash
   gh release create vX.Y.Z --title "X.Y.Z - <theme>" --notes-file release-notes.md
   ```

5. Deploy by pulling `ghcr.io/magnusfrodell/etd-report-scheduler:X.Y.Z` before pointing the container at the new tag.
