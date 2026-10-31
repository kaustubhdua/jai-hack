"""Dedicated Vercel function route for /api/analyze/batch."""
from fastapi import FastAPI, Request

from api.index import BatchAnalyzeRequest, analyze_batch

app = FastAPI()


@app.post("/")
@app.post("/batch")
@app.post("/api/analyze/batch")
def route_analyze_batch(payload: BatchAnalyzeRequest, request: Request):
    return analyze_batch(payload, request)
