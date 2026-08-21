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
    assert {
        'ptrclassify:allocation="dynamic"',
        'ptrclassify:access="mobile"',
        'ptrclassify:translation="nat"',
    } <= got


def test_aws_ec2():
    c = PTRClassifier().classify(
        "120.166.151.3.in-addr.arpa. PTR ec2-3-151-166-120.us-east-2.compute.amazonaws.com."
    )
    got = set(c.values())
    assert {
        'ptrclassify:provider="amazon-aws"',
        'ptrclassify:hosting="cloud"',
        'ptrclassify:hosting="datacenter"',
        'ptrclassify:role="virtual-machine"',
        'ptrclassify:naming="ip-encoded"',
    } <= got
    assert c.hints["cloud_region"] == "us-east-2"


def test_router_loopback():
    got = values("lo0-0.mrsnqe30.dk.ip.tdc.net")
    assert {'ptrclassify:role="router"', 'ptrclassify:role="loopback-interface"'} <= got


def test_bras():
    got = values("bras-base-toroon4443w-grc-100-184-146-120-165.dsl.bell.ca")
    assert {
        'ptrclassify:role="router"',
        'ptrclassify:role="broadband-aggregation"',
        'ptrclassify:access="dsl"',
    } <= got


def test_cname_is_not_ptr_classified():
    c = PTRClassifier().classify(
        "48.81.85.88.in-addr.arpa. CNAME 48.0-26.81.85.88.in-addr.arpa."
    )
    assert c.values() == ['ptrclassify:dns="cname"']


def test_all_sample_records_classify_without_error():
    from pathlib import Path
    classifier = PTRClassifier()
    sample = Path(__file__).parent / "data" / "sample.ptr"
    rows = [line for line in sample.read_text().splitlines() if line.strip()]
    assert len(rows) == 100
    for row in rows:
        classifier.classify(row)


def test_misp_taxonomy_covers_every_classifier_label():
    import json
    from pathlib import Path

    taxonomy_path = Path(__file__).parents[1] / "misp-taxonomy" / "machinetag.json"
    taxonomy = json.loads(taxonomy_path.read_text())
    declared = {
        (group["predicate"], entry["value"])
        for group in taxonomy["values"]
        for entry in group["entry"]
    }

    rules_path = (
        Path(__file__).parents[1]
        / "build"
        / "lib"
        / "ptrclassify"
        / "data"
        / "rules.json"
    )
    rules = json.loads(rules_path.read_text())
    generated = {("naming", "ip-encoded"), ("naming", "generic-reverse"), ("dns", "cname")}
    assert {(rule["category"], rule["label"]) for rule in rules} | generated <= declared
    assert taxonomy["namespace"] == "ptrclassify"
