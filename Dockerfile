FROM node:22-alpine AS ui-build
WORKDIR /ui
COPY frontend/package*.json ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/dlp/backend DLP_PROFILE_DIR=/opt/dlp/profiles
WORKDIR /opt/dlp
COPY backend/pyproject.toml ./backend/pyproject.toml
COPY backend/app/ ./backend/app/
RUN pip install --no-cache-dir ./backend && useradd --create-home --uid 10001 --shell /usr/sbin/nologin dlp
COPY profiles/ ./profiles/
COPY --from=ui-build /ui/dist ./frontend/dist/
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=4s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=2)"
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-access-log"]
