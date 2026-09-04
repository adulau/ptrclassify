import csv
import io
import json

import pytest

from ptrclassify import PTRClassifier
from ptrclassify.csv_cli import enrich_csv, main


def test_enrich_csv_preserves_rows_and_adds_labels_and_json_classification():
    source = io.StringIO(
        "id,ptr,comment\r\n"
        '1,188.147.228.101.nat.umts.dynamic.t-mobile.pl.,"mobile, subscriber"\r\n'
        "2,ec2-3-151-166-120.us-east-2.compute.amazonaws.com.,cloud\r\n"
    )
    destination = io.StringIO(newline="")

    enrich_csv(source, destination, PTRClassifier())

    rows = list(csv.DictReader(io.StringIO(destination.getvalue())))
    assert [row["id"] for row in rows] == ["1", "2"]
    assert rows[0]["comment"] == "mobile, subscriber"
    first = json.loads(rows[0]["ptrclassify"])
    second = json.loads(rows[1]["ptrclassify"])
    assert json.loads(rows[0]["ptrclassify_labels"]) == [
        label["value"] for label in first["labels"]
    ]
    assert first["input"] == "188.147.228.101.nat.umts.dynamic.t-mobile.pl."
    assert 'ptrclassify:access="mobile"' in {
        label["value"] for label in first["labels"]
    }
    assert second["hints"]["cloud_region"] == "us-east-2"


def test_enrich_csv_supports_custom_fields():
    source = io.StringIO("hostname\nrouter.example.net\n")
    destination = io.StringIO()

    enrich_csv(
        source,
        destination,
        PTRClassifier(),
        ptr_field="hostname",
        output_field="classification",
        labels_field="labels",
    )

    row = next(csv.DictReader(io.StringIO(destination.getvalue())))
    assert json.loads(row["labels"]) == ['ptrclassify:role="router"']
    assert json.loads(row["classification"])["hostname"] == "router.example.net"


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        ("", "missing a header row"),
        ("hostname\nexample.net\n", "missing required field 'ptr'"),
        ("ptr,ptrclassify\nexample.net,old\n", "already contains output field"),
        ("ptr,ptrclassify_labels\nexample.net,old\n", "already contains labels field"),
    ],
)
def test_enrich_csv_rejects_invalid_headers(contents, message):
    with pytest.raises(ValueError, match=message):
        enrich_csv(io.StringIO(contents), io.StringIO(), PTRClassifier())


def test_main_reads_and_writes_named_files(tmp_path):
    source = tmp_path / "input.csv"
    destination = tmp_path / "output.csv"
    source.write_text("ptr\nrouter.example.net\n", encoding="utf-8")

    assert main([str(source), str(destination)]) == 0

    row = next(csv.DictReader(destination.open(encoding="utf-8")))
    assert json.loads(row["ptrclassify"])["hostname"] == "router.example.net"


def test_main_supports_custom_labels_field(tmp_path):
    source = tmp_path / "input.csv"
    destination = tmp_path / "output.csv"
    source.write_text(
        "ptr\nec2-3-151-166-120.us-east-2.compute.amazonaws.com.\n",
        encoding="utf-8",
    )

    assert main(["--labels-field", "labels", str(source), str(destination)]) == 0

    row = next(csv.DictReader(destination.open(encoding="utf-8")))
    assert 'ptrclassify:hosting="cloud"' in json.loads(row["labels"])


def test_enrich_csv_requires_distinct_output_fields():
    with pytest.raises(ValueError, match="must be different"):
        enrich_csv(
            io.StringIO("ptr\nexample.net\n"),
            io.StringIO(),
            PTRClassifier(),
            output_field="result",
            labels_field="result",
        )
