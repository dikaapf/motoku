FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    MOTOKU_HOST=0.0.0.0 \
    MOTOKU_PORT=5000

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libxml2-dev \
        libxslt1-dev \
        whois \
        nmap \
        chromium \
        libimage-exiftool-perl \
        tesseract-ocr \
        tesseract-ocr-ind \
        fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .

RUN mkdir -p data \
    && useradd --create-home appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/readyz', timeout=4).status == 200 else 1)"

ENV MOTOKU_CHROMIUM_PATH=/usr/bin/chromium

# gthread workers keep Server-Sent Events progress streams from blocking requests.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--worker-class", "gthread", \
     "--threads", "16", "--timeout", "120", "app:app"]
