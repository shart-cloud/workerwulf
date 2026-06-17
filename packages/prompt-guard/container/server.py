"""Llama Prompt Guard 2 86M — FastAPI inference server."""

import time
import torch
from fastapi import FastAPI
from pydantic import BaseModel
from transformers import AutoTokenizer, AutoModelForSequenceClassification

app = FastAPI()

MODEL_ID = "meta-llama/Llama-Prompt-Guard-2-86M"
tokenizer = None
model = None


class ClassifyRequest(BaseModel):
    text: str


class ClassifyResponse(BaseModel):
    label: str
    score: float
    logits: dict
    latency_ms: int


@app.on_event("startup")
def load_model():
    global tokenizer, model
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID)
    model.eval()


@app.get("/health")
def health():
    return {"status": "ok", "model": MODEL_ID, "loaded": model is not None}


@app.post("/classify", response_model=ClassifyResponse)
def classify(req: ClassifyRequest):
    t0 = time.monotonic()

    inputs = tokenizer(
        req.text,
        return_tensors="pt",
        truncation=True,
        max_length=512,
    )

    with torch.no_grad():
        logits = model(**inputs).logits

    probs = torch.softmax(logits, dim=-1)
    predicted_class = logits.argmax().item()
    label = model.config.id2label[predicted_class]
    score = probs[0][predicted_class].item()

    latency_ms = int((time.monotonic() - t0) * 1000)

    return ClassifyResponse(
        label=label,
        score=score,
        logits={
            "benign": logits[0][0].item(),
            "malicious": logits[0][1].item(),
        },
        latency_ms=latency_ms,
    )
