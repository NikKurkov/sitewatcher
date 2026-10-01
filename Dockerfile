FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/data/sitewatcher.db \
    XDG_CACHE_HOME=/data/cache

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir . \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin sitewatcher \
    && mkdir -p /data \
    && chown sitewatcher:sitewatcher /data

USER sitewatcher
CMD ["sitewatcher", "bot"]
