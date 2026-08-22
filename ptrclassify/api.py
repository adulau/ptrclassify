"""HTTP API for classifying one or more PTR records."""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .classifier import PTRClassifier


class LookupRequest(BaseModel):
    """PTR records or hostnames to classify."""

    records: list[str] = Field(
        ...,
        min_items=1,
        description="One or more PTR hostnames or complete DNS PTR records.",
        examples=[
            [
                "101.228.147.188.in-addr.arpa. PTR "
                "188.147.228.101.nat.umts.dynamic.t-mobile.pl."
            ]
        ],
    )


class LabelResponse(BaseModel):
    """One explainable classification label."""

    category: str
    label: str
    confidence: float
    evidence: list[str]
    rule_ids: list[str]
    description: str | None = None
    value: str


class LocationCandidateResponse(BaseModel):
    """A possible place decoded from an operator-specific hostname token."""

    code: str
    confidence: float
    evidence: str
    rule_id: str
    city: str | None = None
    region: str | None = None
    country: str | None = None
    description: str | None = None


class ClassificationResponse(BaseModel):
    """Classification of a single submitted PTR record."""

    input: str
    hostname: str | None
    address: str | None = None
    record_type: str | None = None
    labels: list[LabelResponse]
    locations: list[LocationCandidateResponse]
    hints: dict[str, Any]


class LookupResponse(BaseModel):
    """Classification results in the same order as the request."""

    results: list[ClassificationResponse]


app = FastAPI(
    title="ptrclassify API",
    version="0.1.0",
    description=(
        "Explainable heuristic classification for reverse-DNS PTR hostnames. "
        "PTR names are operator-controlled, so results are inferences rather than facts."
    ),
)
classifier = PTRClassifier()


@app.get("/health", tags=["service"])
def health() -> dict[str, str]:
    """Report that the service is ready to accept requests."""

    return {"status": "ok"}


@app.post("/lookup", response_model=LookupResponse, tags=["PTR records"])
def lookup(request: LookupRequest) -> LookupResponse:
    """Classify one or more PTR hostnames or complete PTR record lines."""

    return LookupResponse(
        results=[classifier.classify(record).to_dict() for record in request.records]
    )


def main() -> None:
    """Run the API using the development-friendly Uvicorn server."""

    import uvicorn

    uvicorn.run("ptrclassify.api:app", host="0.0.0.0", port=8000)
