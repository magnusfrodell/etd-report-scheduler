# Contributing

Thanks for taking the time to contribute. This is a community sample - issues and
pull requests are welcome, TAC cases are not (the code is not a Cisco product).

## Development setup

```bash
git clone https://github.com/magnusfrodell/etd-report-scheduler.git
cd etd-report-scheduler
python3 -m venv venv && source venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env            # fill in SECRET_KEY, ENCRYPTION_KEY, ADMIN_PASSWORD
pytest                          # 20 tests, fake ETD API, no network needed
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
