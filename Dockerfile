FROM python:3.11-slim

# System deps for Playwright (Chromium + Firefox + WebKit)
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget gnupg2 curl ca-certificates \
    fonts-noto fonts-dejavu fonts-liberation \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
    libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 \
    libxfixes3 libxrandr2 libgbm1 libasound2 \
    libpango-1.0-0 libpangocairo-1.0-0 libgtk-3-0 \
    libwebkitgtk-6.0-dev libgstreamer-gl1.0-0 libgstreamer-plugins-base1.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install chromium firefox webkit

COPY app/ .

EXPOSE 8000

ENV ADMIN_PASSWORD=QaSuite2026!
ENV JWT_SECRET=argitic-qa-suite-jwt-secret-v1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
