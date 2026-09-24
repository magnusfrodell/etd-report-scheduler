# ETD Report Scheduler - single-container image
#
# Build:  docker build -t etd-report-scheduler .
# Run:    docker run -d --name etd-reports --env-file .env -p 8080:8080 -v etd-data:/data etd-report-scheduler
# Pinned by digest (multi-arch index) so a rebuild gives the same base; Dependabot proposes updates.
FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DATA_DIR=/data \
    FORWARDED_ALLOW_IPS=127.0.0.1

# WeasyPrint (PDF rendering) needs Pango; fonts-dejavu gives PDFs a sane default font.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY . .

RUN useradd --system --uid 10001 --home /app app \
 && mkdir -p /data && chown -R app:app /data /app
USER app

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/api/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
