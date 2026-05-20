# SmartFuzz backend — Flask + Playwright + SocketIO
FROM python:3.11-slim

# System libs Playwright/Chromium needs. `--no-install-recommends` keeps the
# image lean; the parallel `playwright install --with-deps` below backfills
# anything we miss.
RUN apt-get update && apt-get install -y --no-install-recommends \
      wget \
      gnupg \
      ca-certificates \
      fonts-liberation \
      libnss3 \
      libatk1.0-0 \
      libatk-bridge2.0-0 \
      libcups2 \
      libxkbcommon0 \
      libxcomposite1 \
      libxdamage1 \
      libxrandr2 \
      libgbm1 \
      libpango-1.0-0 \
      libasound2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first so the layer caches across code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download the Chromium build Playwright actually drives.
RUN playwright install chromium --with-deps

# Application code (after dependency install for cache efficiency).
COPY . .

EXPOSE 5000

# `python app.py` honours $PORT and $FLASK_DEBUG (set by docker-compose).
CMD ["python", "app.py"]
