FROM python:3.11-slim

WORKDIR /app

# Semgrep needs git for its rule fetch; build-essential is needed for some
# transitive deps to build wheels.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-fetch the Semgrep rule packs so CodeShield doesn't pay the cost on first scan.
RUN semgrep --version

# Bake the gated Prompt Guard 2 model weights into the image at build time.
# Requires HF_TOKEN as a build arg. The HF account behind the token must have
# accepted the Llama 4 Community License for Llama-Prompt-Guard-2-86M.
#   docker build --build-arg HF_TOKEN=hf_xxx -t wulf-llamafirewall:v1 ./container
ARG HF_TOKEN=""
ENV HF_TOKEN=${HF_TOKEN}
RUN python -c "from transformers import AutoTokenizer, AutoModelForSequenceClassification; \
AutoTokenizer.from_pretrained('meta-llama/Llama-Prompt-Guard-2-86M'); \
AutoModelForSequenceClassification.from_pretrained('meta-llama/Llama-Prompt-Guard-2-86M')"

COPY wulf-rules.yml .
COPY wulf_scanners.py .
COPY server.py .

EXPOSE 8000
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
