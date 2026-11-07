FROM node:22-alpine AS ui-build
WORKDIR /ui
COPY frontend/package*.json ./
RUN npm ci --no-audit --no-fund
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
# Select package indexes one at a time (never --extra-index-url) to avoid
# dependency confusion and tolerate inaccessible upstream PyPI networks.
# Only HTTPS indexes are allowed; TLS certificate checks remain enabled.
ARG PIP_INDEX_PRIMARY=https://package-mirror.liara.ir/repository/pypi/simple/
ARG PIP_INDEX_SECONDARY=https://mirror2.chabokan.net/pypi/simple/
ARG PIP_INDEX_FALLBACK=https://pypi.org/simple/
ARG PIP_DEFAULT_TIMEOUT=30
ARG PIP_RETRIES=2
ARG PIP_DISABLE_PIP_VERSION_CHECK=1
RUN set -eu; \
    unset PIP_EXTRA_INDEX_URL; \
    installed=0; \
    for index in "$PIP_INDEX_PRIMARY" "$PIP_INDEX_SECONDARY" "$PIP_INDEX_FALLBACK"; do \
      case "$index" in https://*) ;; *) echo "Refusing non-HTTPS PyPI index" >&2; exit 1 ;; esac; \
      echo "Trying Python package index: $index"; \
      if PIP_INDEX_URL="$index" python -m pip install --no-cache-dir --upgrade pip setuptools wheel \
         && PIP_INDEX_URL="$index" python -m pip install --no-cache-dir --no-build-isolation ./backend; then \
        installed=1; \
        break; \
      fi; \
      echo "Python package index failed; trying next configured index" >&2; \
    done; \
    if [ "$installed" -ne 1 ]; then \
      echo "ERROR: Python dependency installation failed on every configured index" >&2; \
      exit 1; \
    fi; \
    useradd --create-home --uid 10001 --shell /usr/sbin/nologin dlp
COPY profiles/ ./profiles/
COPY --from=ui-build /ui/dist ./frontend/dist/
USER 10001:10001
EXPOSE 8484
HEALTHCHECK --interval=30s --timeout=4s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8484/health',timeout=2)"
# Two workers so /health stays up while one worker runs a heavy encode.
# Long timeout: single-shot ≤48 MiB SOC CSV can take minutes of CPU-bound detection.
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8484", "--workers", "2", "--timeout-keep-alive", "75", "--proxy-headers", "--no-access-log"]
