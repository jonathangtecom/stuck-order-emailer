FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/data/templates

# Git commit for Sentry release tracking (build with --build-arg GIT_COMMIT=$(git rev-parse --short HEAD))
ARG GIT_COMMIT=unknown
ENV SENTRY_RELEASE=stuck-order-emailer@${GIT_COMMIT}

ENV PORT=8080

# Health check for container monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/')" || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "4", "--timeout", "300", "app:app"]
