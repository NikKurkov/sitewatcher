FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/data/sitewatcher.db \
    XDG_CACHE_HOME=/data/cache

RUN apt-get update \
    && apt-get install -y --no-install-recommends traceroute \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# Source changes should reuse the installed runtime dependencies.
COPY pyproject.toml ./
RUN python -c 'import subprocess, sys, tomllib; \
    from pathlib import Path; \
    dependencies = tomllib.loads(Path("pyproject.toml").read_text())["project"]["dependencies"]; \
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--no-cache-dir", *dependencies])'

COPY README.md LICENSE ./
COPY sitewatcher ./sitewatcher
RUN pip install --no-cache-dir --no-deps . \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin sitewatcher \
    && mkdir -p /data \
    && chown sitewatcher:sitewatcher /data

USER sitewatcher
CMD ["sitewatcher", "web"]
