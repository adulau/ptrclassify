import csv
import io
import json

import pytest

from ptrclassify import PTRClassifier
from ptrclassify.csv_cli import enrich_csv, main


def test_enrich_csv_preserves_rows_and_adds_json_classification():
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
    )

    row = next(csv.DictReader(io.StringIO(destination.getvalue())))
    assert json.loads(row["classification"])["hostname"] == "router.example.net"


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        ("", "missing a header row"),
        ("hostname\nexample.net\n", "missing required field 'ptr'"),
        ("ptr,ptrclassify\nexample.net,old\n", "already contains output field"),
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
