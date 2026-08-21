# ptrclassify

`ptrclassify` is a small, dependency-free Python library and CLI that infers likely IP usage from reverse-DNS PTR hostnames.

It is intentionally **heuristic and multi-label**. PTR naming is operator-controlled and is not authoritative evidence of how an address is actually used. The output therefore includes a confidence score, the text that matched, and the rule IDs that produced each label.

Examples of orthogonal labels:

- `allocation:dynamic`, `allocation:static`, `allocation:reserved`
- `access:residential`, `access:business`, `access:mobile`, `access:cable`, `access:dsl`, `access:fiber`, `access:wireless`, `access:broadband`
- `translation:nat`, `translation:cgnat`
- `role:customer`, `role:router`, `role:broadband-aggregation`, `role:loopback-interface`, `role:virtual-machine`, `role:vpn`, `role:voip`
- `hosting:cloud`, `hosting:datacenter`, `hosting:hosting`, `hosting:cdn`
- `network:anycast`, `network:dedicated-internet`
- `organization:education`, `organization:government`, `organization:military`
- `provider:amazon-aws`, `provider:google-cloud`, `provider:oracle-cloud`, `provider:akamai`, ...
- `naming:ip-encoded`, `naming:generic-reverse`

## Install

```bash
python -m pip install .
```

Or for development:

```bash
python -m pip install -e .
```

## Library API

```python
from ptrclassify import classify, PTRClassifier

labels = classify("188.147.228.101.nat.umts.dynamic.t-mobile.pl.")
for label in labels:
    print(label.value, label.confidence)

classifier = PTRClassifier()
result = classifier.classify(
    "101.228.147.188.in-addr.arpa. PTR 188.147.228.101.nat.umts.dynamic.t-mobile.pl."
)
print(result.values())
print(result.to_dict())
```

Expected high-confidence labels include:

```text
allocation:dynamic
access:mobile
translation:nat
```

## CLI

Single hostname:

```bash
ptrclassify 'ec2-3-151-166-120.us-east-2.compute.amazonaws.com.'
```

Complete DNS record:

```bash
ptrclassify '120.166.151.3.in-addr.arpa. PTR ec2-3-151-166-120.us-east-2.compute.amazonaws.com.'
```

File / JSONL:

```bash
ptrclassify --file tests/data/sample.ptr --json > classifications.jsonl
```

Just labels:

```bash
ptrclassify --values-only '86-45-50-202-dynamic.agg1.cab.bdt-fng.eircom.net.'
```

## Rule model

Built-in rules live in `ptrclassify/data/rules.json`. Rules are regular-expression based and have this shape:

```json
{
  "id": "access.mobile",
  "category": "access",
  "label": "mobile",
  "confidence": 0.98,
  "patterns": ["(?:^|[._-])mobile(?:[._-]|$)", "(?:^|[._-])umts(?:[._-]|$)"]
}
```

You can add private/local rules without modifying the package:

```python
from ptrclassify import PTRClassifier

classifier = PTRClassifier(extra_rules=[{
    "id": "myisp.cgn",
    "category": "translation",
    "label": "cgnat",
    "confidence": 0.99,
    "patterns": [r"\\.cgn\\.example\\.net$"],
}])
```

## Design notes

The design follows the same general idea used by Internet-topology work such as CAIDA Hoiho: operator naming conventions can be mined as evidence, but should be treated as inference rather than truth. This package focuses on usage/allocation/service classes instead of primarily extracting router geolocation.

Provider-specific rules are intentionally separated from generic tokens. This avoids dangerous inferences such as classifying every `softbank...` hostname as mobile simply because SoftBank also operates mobile networks.

For production enrichment, PTR classification is best combined with ASN/RDAP, BGP prefix data, geofeeds, known cloud/hosting prefixes, forward-confirmed reverse DNS (FCrDNS), and active/service observations.

## References / prior art

- RFC 8501, *Reverse DNS in IPv6 for Internet Service Providers*: discusses static, dynamic and dynamically generated reverse names and warns against over-interpreting PTR data.
- CAIDA Hoiho / ITDK: learns operator-specific regular expressions from router hostnames for infrastructure/geolocation inference; this project borrows the explainable-regex philosophy for a different taxonomy.
- AWS EC2 public hostname documentation: documents the `ec2-A-B-C-D.<region>.compute.amazonaws.com` form used by the provider-specific rules.

The built-in taxonomy is not claimed to be an Internet standard. It is designed as a practical, extensible CTI/network-enrichment taxonomy with orthogonal namespaces instead of a single mutually-exclusive class.
