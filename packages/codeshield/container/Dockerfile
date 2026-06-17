FROM python:3.11-slim

WORKDIR /app

# Semgrep needs git for its rule registry fetch even when we use local rules.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-fetch Semgrep rule packs so first scan is fast.
RUN semgrep --version

COPY wulf-rules.yml .
COPY server.py .

EXPOSE 8000
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
