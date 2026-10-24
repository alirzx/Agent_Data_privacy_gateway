FROM node:22-alpine AS ui-build
WORKDIR /ui
COPY frontend/package*.json ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/dlp/backend DLP_PROFILE_DIR=/opt/dlp/profiles
WORKDIR /opt/dlp
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY backend/pyproject.toml ./backend/pyproject.toml
COPY backend/app/ ./backend/app/
# Preinstall build tooling in the image env; isolated PEP517 builds often fail
# when the builder cannot reach PyPI for setuptools (versions: none).
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
 && pip install --no-cache-dir --no-build-isolation ./backend \
 && useradd --create-home --uid 10001 --shell /usr/sbin/nologin dlp
COPY profiles/ ./profiles/
COPY --from=ui-build /ui/dist ./frontend/dist/
USER 10001:10001
EXPOSE 8484
HEALTHCHECK --interval=30s --timeout=4s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8484/health',timeout=2)"
# Two workers so /health stays up while one worker runs a heavy encode.
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8484", "--workers", "2", "--proxy-headers", "--no-access-log"]
