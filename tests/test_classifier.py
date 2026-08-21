from ptrclassify import PTRClassifier, classify, parse_ptr_record


def values(value: str) -> set[str]:
    return {x.value for x in classify(value)}


def test_parse_full_ptr_line():
    record = parse_ptr_record(
        "101.228.147.188.in-addr.arpa. PTR 188.147.228.101.nat.umts.dynamic.t-mobile.pl."
    )
    assert record.address == "188.147.228.101"
    assert record.hostname == "188.147.228.101.nat.umts.dynamic.t-mobile.pl"


def test_dynamic_mobile_nat():
    got = values("188.147.228.101.nat.umts.dynamic.t-mobile.pl")
    assert {"allocation:dynamic", "access:mobile", "translation:nat"} <= got


def test_aws_ec2():
    c = PTRClassifier().classify(
        "120.166.151.3.in-addr.arpa. PTR ec2-3-151-166-120.us-east-2.compute.amazonaws.com."
    )
    got = set(c.values())
    assert {"provider:amazon-aws", "hosting:cloud", "hosting:datacenter", "role:virtual-machine", "naming:ip-encoded"} <= got
    assert c.hints["cloud_region"] == "us-east-2"


def test_router_loopback():
    got = values("lo0-0.mrsnqe30.dk.ip.tdc.net")
    assert {"role:router", "role:loopback-interface"} <= got


def test_bras():
    got = values("bras-base-toroon4443w-grc-100-184-146-120-165.dsl.bell.ca")
    assert {"role:router", "role:broadband-aggregation", "access:dsl"} <= got


def test_cname_is_not_ptr_classified():
    c = PTRClassifier().classify(
        "48.81.85.88.in-addr.arpa. CNAME 48.0-26.81.85.88.in-addr.arpa."
    )
    assert c.values() == ["dns:cname"]


def test_all_sample_records_classify_without_error():
    from pathlib import Path
    classifier = PTRClassifier()
    sample = Path(__file__).parent / "data" / "sample.ptr"
    rows = [line for line in sample.read_text().splitlines() if line.strip()]
    assert len(rows) == 100
    for row in rows:
        classifier.classify(row)
