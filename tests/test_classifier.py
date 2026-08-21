import re
from types import SimpleNamespace

import pytest

from ptrclassify import PTRClassifier, classify, parse_ptr_record


def test_hyperscan_engine_matches_standard_engine(monkeypatch):
    class FakeDatabase:
        def compile(self, expressions, ids, flags):
            self.patterns = [
                (pattern.decode(), pattern_id)
                for pattern, pattern_id in zip(expressions, ids)
            ]

        def scan(self, subject, match_event_handler):
            text = subject.decode()
            for pattern, pattern_id in self.patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    match_event_handler(pattern_id, match.start(), match.end(), 0, None)

    fake_hyperscan = SimpleNamespace(
        Database=FakeDatabase,
        HS_FLAG_CASELESS=1,
        HS_FLAG_SOM_LEFTMOST=2,
    )
    monkeypatch.setattr("ptrclassify.classifier.import_module", lambda _name: fake_hyperscan)

    hostname = (
        "120.166.151.3.in-addr.arpa. PTR "
        "ec2-3-151-166-120.us-east-2.compute.amazonaws.com."
    )
    hyperscan_result = PTRClassifier(engine="hyperscan").classify(hostname).to_dict()
    assert hyperscan_result == PTRClassifier().classify(hostname).to_dict()


def test_unknown_regexp_engine_is_rejected():
    with pytest.raises(ValueError, match="engine must be"):
        PTRClassifier(engine="unknown")


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


@pytest.mark.parametrize(
    ("hostname", "expected"),
    [
        (
            "217-62-56-51.cable.dynamic.v4.ziggo.nl",
            {
                'ptrclassify:allocation="dynamic"',
                'ptrclassify:access="cable"',
                'ptrclassify:access="residential"',
            },
        ),
        (
            "pool-74-96-220-47.washdc.fios.verizon.net",
            {
                'ptrclassify:allocation="dynamic"',
                'ptrclassify:access="fiber"',
                'ptrclassify:access="residential"',
            },
        ),
        (
            "45-18-251-200.lightspeed.miamfl.sbcglobal.net",
            {
                'ptrclassify:access="dsl"',
                'ptrclassify:access="residential"',
            },
        ),
        (
            "ool-18bdf614.dyn.optonline.net",
            {
                'ptrclassify:allocation="dynamic"',
                'ptrclassify:access="cable"',
                'ptrclassify:access="residential"',
            },
        ),
        (
            "dsl-208-230-135-189-dynamic.prod-infinitum.com.mx",
            {
                'ptrclassify:allocation="dynamic"',
                'ptrclassify:access="dsl"',
                'ptrclassify:access="residential"',
            },
        ),
        (
            "vps-56086a54.vps.ovh.net",
            {
                'ptrclassify:hosting="hosting"',
                'ptrclassify:hosting="datacenter"',
                'ptrclassify:role="virtual-machine"',
            },
        ),
        (
            "syn-150-220-194-060.biz.spectrum.com",
            {'ptrclassify:access="business"'},
        ),
        (
            "cpe-121-208-95-134.qb51.nqld.asp.telstra.net",
            {
                'ptrclassify:access="residential"',
                'ptrclassify:role="customer"',
            },
        ),
    ],
)
def test_sample_isp_templates(hostname, expected):
    assert expected <= values(hostname)


@pytest.mark.parametrize(
    ("hostname", "expected"),
    [
        ("p3810018-ipxg12301sapodori.hokkaido.ocn.ne.jp", {"residential", "broadband"}),
        ("207.240.114.89.rev.vodafone.pt", {"residential", "broadband"}),
        ("pool-246-114-123-181.telecel.com.py", {"mobile", "customer"}),
        ("191.31.240.210.dynamic.adsl.gvt.net.br", {"residential", "dsl"}),
        ("217-209-174-218-no600.tbcn.telia.com", {"residential"}),
        ("host-82-58-205-5.retail.telecomitalia.it", {"residential", "dsl"}),
        ("host-2-102-205-112.as13285.net", {"residential"}),
        ("n58-104-225-87.mrk2.qld.optusnet.com.au", {"residential"}),
        ("S0106400fc14910b0.wk.shawcable.net", {"residential", "cable"}),
        ("a89-155-58-205.cpe.netcabo.pt", {"residential", "cable"}),
        ("50-78-234-6-static.hfc.comcastbusiness.net", {"business", "cable"}),
    ],
)
def test_additional_isp_domain_rules(hostname, expected):
    got = {label.label for label in classify(hostname)}
    assert expected <= got


@pytest.mark.parametrize(
    "hostname",
    [
        "vmi2847648.contaboserver.net",
        "66.55.149.8.choopa.net",
        "lvps87-230-81-0.dedicated.hosteurope.de",
    ],
)
def test_additional_hosting_domain_rules(hostname):
    assert {"hosting", "datacenter"} <= {label.label for label in classify(hostname)}


@pytest.mark.parametrize(
    ("hostname", "expected"),
    [
        ("ecs-60-202-166-148.compute.hwclouds-dns.com", {"cloud", "datacenter", "virtual-machine", "huawei-cloud"}),
        ("45.76.93.56.vultrusercontent.com", {"cloud", "datacenter", "virtual-machine", "vultr"}),
        ("static.154.119.217.95.clients.your-server.de", {"hosting", "datacenter", "hetzner"}),
        ("a104-99-31-223.deploy.static.akamaitechnologies.com", {"cdn", "datacenter", "akamai"}),
        ("KD113144064163.ppp-bb.dion.ne.jp", {"residential", "broadband", "dialup-ppp"}),
        ("c9501775.virtua.com.br", {"residential", "broadband", "cable"}),
        ("193-253-51-239.ftth.fr.orangecustomers.net", {"residential", "fiber"}),
        ("167-234-233-166.mobile.uscc.net", {"mobile", "customer"}),
        ("83-232-170-93.biz.kpn.net", {"business"}),
    ],
)
def test_new_operator_cloud_datacenter_and_cdn_rules(hostname, expected):
    assert expected <= {label.label for label in classify(hostname)}


@pytest.mark.parametrize(
    ("hostname", "expected"),
    [
        ("cm125-59-176-66.hkcable.com.hk", {"residential", "cable"}),
        ("14-133-116-213.area7c.commufa.jp", {"residential", "fiber"}),
        ("176-137-80-68.abo.bbox.fr", {"residential", "broadband"}),
        ("cpe-110-147-24-50.bpbn-r-032.cht.nsw.bigpond.net.au", {"residential", "broadband", "customer"}),
        ("host81-139-234-82.in-addr.btopenworld.com", {"residential", "broadband"}),
        ("d8D860B54.access.telenet.be", {"residential", "cable"}),
        ("220-235-88-7.dyn.iinet.net.au", {"residential", "broadband", "dynamic"}),
        ("85.103.149.119.dynamic.ttnet.com.tr", {"residential", "dsl", "dynamic"}),
        ("b5d53bb8.virtua.com.br", {"residential", "broadband", "cable"}),
        ("109.58.95.218.mobile.3.dk", {"mobile", "customer"}),
        ("77.119.13.156.wireless.dyn.drei.com", {"mobile", "customer", "dynamic"}),
        ("host-82-104-78-219.business.telecomitalia.it", {"business", "dsl"}),
        ("ec2-16-140-70-10.ap-southeast-4.compute.amazonaws.com", {"cloud", "datacenter", "virtual-machine", "amazon-aws"}),
        ("oc-129-148-242-116.compute.oraclecloud.com", {"cloud", "datacenter", "virtual-machine", "oracle-cloud"}),
        ("server-3-162-174-12.ord56.r.cloudfront.net", {"cdn", "datacenter", "amazon-cloudfront"}),
        ("a23-62-5-235.deploy.static.akamaitechnologies.com", {"cdn", "datacenter", "akamai"}),
        ("mta-225.fi2.lnmailer.net", {"hosting", "datacenter", "server"}),
    ],
)
def test_requested_operator_hosting_and_cdn_templates(hostname, expected):
    assert expected <= {label.label for label in classify(hostname)}
