import json
from pathlib import Path

from fastapi.testclient import TestClient

from ptrclassify.api import app


client = TestClient(app)


def test_lookup_one_or_more_ptr_records():
    response = client.post(
        "/lookup",
        json={
            "records": [
                "ec2-3-151-166-120.us-east-2.compute.amazonaws.com.",
                "188.147.228.101.nat.umts.dynamic.t-mobile.pl.",
            ]
        },
    )

    assert response.status_code == 200
    results = response.json()["results"]
    assert len(results) == 2
    assert any(label["label"] == "cloud" for label in results[0]["labels"])
    assert any(label["label"] == "mobile" for label in results[1]["labels"])
    assert results[0]["locations"] == []


def test_lookup_requires_at_least_one_record():
    response = client.post("/lookup", json={"records": []})
    assert response.status_code == 422


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_checked_in_openapi_document_describes_the_service():
    document = json.loads((Path(__file__).parents[1] / "openapi.json").read_text())
    assert document["paths"].keys() == app.openapi()["paths"].keys()
    assert "/lookup" in document["paths"]
