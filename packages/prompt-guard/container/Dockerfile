FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Prompt Guard 2 is gated behind the Llama 4 Community License. Accept it on
# huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M, then build with:
#   docker build --build-arg HF_TOKEN=hf_xxx -t wulf-prompt-guard ./container
# wrangler's container build does NOT pass --build-arg, so for `wrangler deploy`
# you must pre-build the image locally and reference it via image tag in
# wrangler.toml, OR push to a registry that wrangler can pull from.
ARG HF_TOKEN=""
ENV HF_TOKEN=${HF_TOKEN}
RUN python -c "from transformers import AutoTokenizer, AutoModelForSequenceClassification; \
AutoTokenizer.from_pretrained('meta-llama/Llama-Prompt-Guard-2-86M'); \
AutoModelForSequenceClassification.from_pretrained('meta-llama/Llama-Prompt-Guard-2-86M')"

COPY server.py .

EXPOSE 8000
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
