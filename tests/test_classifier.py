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


@pytest.mark.parametrize(
    ("hostname", "expected"),
    [
        (
            "pool-74-96-220-47.washdc.fios.verizon.net",
            {"code": "washdc", "city": "Washington", "country": "US"},
        ),
        (
            "45-18-251-200.lightspeed.miamfl.sbcglobal.net",
            {"code": "miamfl", "city": "Miami", "region": "Florida"},
        ),
        (
            "server-3-162-174-12.ord56.r.cloudfront.net",
            {"code": "ord", "city": "Chicago", "country": "US"},
        ),
        (
            "n58-104-225-87.mrk2.qld.optusnet.com.au",
            {"code": "qld", "region": "Queensland", "country": "AU"},
        ),
    ],
)
def test_operator_scoped_location_extraction(hostname, expected):
    result = PTRClassifier().classify(hostname)
    assert result.locations
    serialized = result.to_dict()["locations"][0]
    assert expected.items() <= serialized.items()
    assert serialized["evidence"]
    assert serialized["rule_id"].startswith("location.")


def test_location_tokens_are_not_interpreted_outside_operator_template():
    result = PTRClassifier().classify("ord56.example.net")
    assert result.locations == []


@pytest.mark.parametrize(
    ("hostname", "tld", "country"),
    [
        ("188.147.228.101.nat.umts.dynamic.t-mobile.pl", "pl", "PL"),
        ("host.example.co.uk", "uk", "GB"),
        ("router.example.de.", "de", "DE"),
    ],
)
def test_country_code_tld_adds_country_location(hostname, tld, country):
    locations = PTRClassifier().classify(hostname).locations
    tld_location = next(
        location for location in locations if location.rule_id == "location.country-code-tld"
    )
    assert tld_location.code == tld
    assert tld_location.country == country
    assert tld_location.evidence == f".{tld}"
    assert tld_location.confidence < 0.8


@pytest.mark.parametrize("hostname", ["host.example.com", "ord56.example.net"])
def test_generic_tld_does_not_add_country_location(hostname):
    assert PTRClassifier().classify(hostname).locations == []


@pytest.mark.parametrize(
    ("hostname", "expected"),
    [
        (
            "ec2-3-151-166-120.us-east-2.compute.amazonaws.com",
            {"code": "us-east-2", "region": "Ohio", "country": "US"},
        ),
        (
            "ec2-16-140-70-10.ap-southeast-4.compute.amazonaws.com",
            {"code": "ap-southeast-4", "city": "Melbourne", "country": "AU"},
        ),
        (
            "example-prod.westeurope.cloudapp.azure.com",
            {"code": "westeurope", "country": "NL"},
        ),
        (
            "example-prod.canadacentral.cloudapp.azure.com",
            {"code": "canadacentral", "city": "Toronto", "country": "CA"},
        ),
        (
            "server-1-2-3-4.yyz50.r.cloudfront.net",
            {"code": "yyz", "city": "Toronto", "country": "CA"},
        ),
    ],
)
def test_cloud_and_datacenter_location_extraction(hostname, expected):
    locations = PTRClassifier().classify(hostname).to_dict()["locations"]
    assert locations
    assert expected.items() <= locations[0].items()


@pytest.mark.parametrize(
    ("hostname", "expected"),
    [
        ("example-prod.westeurope.cloudapp.azure.com", {"cloud", "datacenter", "virtual-machine"}),
        ("cache.example.fastly.net", {"cdn", "datacenter"}),
    ],
)
def test_additional_cloud_and_cdn_infrastructure_rules(hostname, expected):
    assert expected <= {label.label for label in classify(hostname)}


def test_private_location_rules_are_extensible():
    classifier = PTRClassifier(extra_location_rules=[{
        "id": "location.example.site",
        "confidence": 0.97,
        "pattern": r"\.(?P<code>hq)\.example\.net$",
        "locations": {
            "hq": {"city": "Example City", "country": "ZZ"},
        },
    }])
    location = classifier.classify("router.hq.example.net").locations[0]
    assert location.city == "Example City"
    assert location.confidence == 0.97


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
        Path(__file__).parents[1] / "ptrclassify" / "data" / "rules.json"
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


@pytest.mark.parametrize(
    ("hostname", "expected_location", "expected_rule"),
    [
        (
            "100ge0-36.core2.lax2.he.net",
            {"code": "lax", "city": "Los Angeles", "country": "US"},
            "location.hurricane-electric.pop",
        ),
        (
            "be3360.ccr42.lax01.atlas.cogentco.com",
            {"code": "lax", "city": "Los Angeles", "country": "US"},
            "location.cogent.pop",
        ),
        (
            "be2317.ccr32.sjc04.atlas.cogentco.com",
            {"code": "sjc", "city": "San Jose", "country": "US"},
            "location.cogent.pop",
        ),
    ],
)
def test_backbone_router_pop_location_and_use(hostname, expected_location, expected_rule):
    result = PTRClassifier().classify(hostname)
    assert 'ptrclassify:role="router"' in result.values()
    assert result.locations
    location = result.locations[0].to_dict()
    assert expected_location.items() <= location.items()
    assert location["rule_id"] == expected_rule


def test_backbone_pop_codes_are_operator_scoped():
    result = PTRClassifier().classify("core2.lax2.example.net")
    assert result.locations == []
    assert 'ptrclassify:role="router"' not in result.values()


@pytest.mark.parametrize(
    ("hostname", "expected"),
    [
        ("mobile-107-239-8-137.mycingular.net", {"mobile", "residential", "customer"}),
        ("ntakta041220.akta.nt.ngn.ppp.infoweb.ne.jp", {"residential", "broadband", "dsl", "dialup-ppp"}),
        ("customer-GDL-105-254.megared.net.mx", {"residential", "cable", "customer"}),
        ("154-174.dsl.iskon.hr", {"residential", "dsl"}),
        ("83-245-148-191.elisa-laajakaista.fi", {"residential", "broadband"}),
        ("152-238-227-242.user.vtal.net.br", {"residential", "fiber", "customer"}),
        ("host-79-50-166-108.retail.telecomitalia.it", {"residential", "dsl"}),
        ("ool-44c0f074.dyn.optonline.net", {"residential", "cable", "dynamic"}),
        ("142.0.36.62.16clouds.com", {"hosting", "datacenter"}),
        ("85-10-137-222.colo.transip.net", {"hosting", "datacenter"}),
        ("nothing.attdns.com", {"reserved"}),
        ("145.172.EARLY-REGISTRATION.of.SURFnet.invalid", {"reserved"}),
    ],
)
def test_observed_operator_templates(hostname, expected):
    assert expected <= {label.label for label in classify(hostname)}


@pytest.mark.parametrize(
    ("hostname", "expected"),
    [
        ("114-35-107-6.hinet-ip.hinet.net", {"residential", "broadband"}),
        ("pw126035247087.25.panda-world.ne.jp", {"residential", "broadband"}),
        ("ti0092a430-1310.bb.online.no", {"residential", "broadband"}),
        ("user-164-126-14-86.play-internet.pl", {"residential", "broadband", "customer"}),
        ("193-45-28-28.customer.telia.com", {"residential", "broadband", "customer"}),
        ("177-103-38-216.dsl.telesp.net.br", {"residential", "dsl"}),
        ("103-80-121-215.customer.node1.com.au", {"residential", "broadband", "customer"}),
        ("ip-64-134-165-39.public.wayport.net", {"wireless", "customer"}),
        ("78-106-113-203.broadband.corbina.ru", {"residential", "broadband"}),
        ("h95-110-29-134.dyn.bashtel.ru", {"dynamic", "residential", "broadband"}),
        ("47.125.159.143.dyn.plus.net", {"dynamic", "residential", "broadband"}),
        ("178235217009.warszawa.vectranet.pl", {"residential", "broadband", "cable"}),
        ("83.0.74.217.internetdsl.tpnet.pl", {"residential", "dsl"}),
        ("253.21-180-91.adsl-dyn.isp.belgacom.be", {"dynamic", "residential", "dsl"}),
        ("061196219030.cidr.odn.ne.jp", {"residential", "broadband"}),
        ("2-54-222-229.orange.net.il", {"residential", "broadband"}),
        ("80-197-93-230-cable.dk.customer.tdc.net", {"residential", "cable", "customer"}),
        ("r167-59-180-237.dialup.adsl.anteldata.net.uy", {"residential", "dsl", "dialup-ppp"}),
        ("adsl-072-151-053-088.sip.bgk.bellsouth.net", {"residential", "dsl"}),
        ("h135-134-223-125.nwblwi.broadband.dynamic.tds.net", {"dynamic", "residential", "broadband"}),
        ("65.220.79.170.in-addr.arpa.verointernet.com.br", {"residential", "broadband"}),
        ("dsl-corp-42-43.transact.bm", {"business", "dsl"}),
        ("83-65-72-102.static.upcbusiness.at", {"static", "business", "cable"}),
        ("ev1s-69-57-129-59.theplanet.com", {"hosting", "datacenter"}),
        ("105.ip-213-32-70.eu", {"hosting", "datacenter"}),
        ("n-hp98.vps.webdock.cloud", {"hosting", "datacenter", "virtual-machine"}),
        ("ip-space.by.proserve.nl", {"hosting", "datacenter"}),
        ("undefined.hostname.localhost", {"reserved"}),
        ("no-reverse-dns.metronet-uk.com", {"reserved"}),
    ],
)
def test_isp_and_hosting_templates_from_august_2026_observations(hostname, expected):
    assert expected <= {label.label for label in classify(hostname)}


@pytest.mark.parametrize(
    ("hostname", "expected"),
    [
        ("188-206-112-135.mobile.kpn.net", {"mobile", "customer"}),
        ("248.109.69.86.rev.sfr.net", {"residential", "broadband"}),
        ("KD106170040172.au-net.ne.jp", {"residential", "broadband"}),
        ("h248.26.191.173.dynamic.ip.windstream.net", {"dynamic", "dsl"}),
        ("adsl-89-217-236-172.adslplus.ch", {"residential", "dsl"}),
        ("122-121-119-37.dynamic-ip.hinet.net", {"residential", "broadband"}),
        ("39.76.140.163.rev.iijmobile.jp", {"mobile", "customer"}),
        ("87-92-12-80.bb.dnainternet.fi", {"residential", "broadband"}),
        ("181-23-243-221.speedy.com.ar", {"residential", "broadband"}),
        ("ac019067.dynamic.ppp.asahi-net.or.jp", {"dynamic", "residential", "customer", "dialup-ppp"}),
        ("ipbcc32f2e.dynamic.kabel-deutschland.de", {"dynamic", "residential", "cable"}),
        ("net-93-71-178-238.cust.vodafonedsl.it", {"residential", "dsl", "customer"}),
        ("m90-141-140-116.cust.tele2.se", {"residential", "broadband", "customer"}),
        ("d24-150-23-131.home.cgocable.net", {"residential", "cable"}),
        ("50-116-38-102.ip.linodeusercontent.com", {"linode", "cloud", "datacenter", "virtual-machine"}),
        ("63-227-183-235.dia.static.qwest.net", {"static", "dedicated-internet", "business"}),
        ("121.242.7.41.static-pune.vsnl.net.in", {"static", "business"}),
        ("204.14.167.96.static.integritynet.com", {"static", "business"}),
        ("pc-49-13-160-190.cm.vtr.net", {"residential", "cable"}),
    ],
)
def test_2026_isp_and_cloud_templates(hostname, expected):
    assert expected <= {label.label for label in classify(hostname)}
