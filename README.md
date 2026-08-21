# ptrclassify

`ptrclassify` is a small, dependency-free Python library and CLI that infers likely IP usage from reverse-DNS PTR hostnames.

It is intentionally **heuristic and multi-label**. PTR naming is operator-controlled and is not authoritative evidence of how an address is actually used. The output therefore includes a confidence score, the text that matched, and the rule IDs that produced each label.

Examples of orthogonal labels:

- `ptrclassify:allocation="dynamic"`, `ptrclassify:allocation="static"`, `ptrclassify:allocation="reserved"`
- `ptrclassify:access="residential"`, `ptrclassify:access="business"`, `ptrclassify:access="mobile"`, ...
- `ptrclassify:translation="nat"`, `ptrclassify:translation="cgnat"`
- `ptrclassify:role="customer"`, `ptrclassify:role="router"`, `ptrclassify:role="broadband-aggregation"`, ...
- `ptrclassify:hosting="cloud"`, `ptrclassify:hosting="datacenter"`, `ptrclassify:hosting="hosting"`, `ptrclassify:hosting="cdn"`
- `ptrclassify:network="anycast"`, `ptrclassify:network="dedicated-internet"`
- `ptrclassify:organization="education"`, `ptrclassify:organization="government"`, `ptrclassify:organization="military"`
- `ptrclassify:provider="amazon-aws"`, `ptrclassify:provider="google-cloud"`, ...
- `ptrclassify:naming="ip-encoded"`, `ptrclassify:naming="generic-reverse"`

## Install

```bash
python -m pip install .
```

Or for development:

```bash
python -m pip install -e .
```

Hyperscan is available as an optional high-throughput matching engine:

```bash
python -m pip install '.[hyperscan]'
ptrclassify --engine hyperscan 'ec2-3-151-166-120.us-east-2.compute.amazonaws.com.'
```

The default `re` engine has no third-party dependencies. The Hyperscan engine
compiles all rule expressions into a single database and returns the same
labels and evidence as the default engine.

## Library API

```python
from ptrclassify import classify, PTRClassifier

labels = classify("188.147.228.101.nat.umts.dynamic.t-mobile.pl.")
for label in labels:
    print(label.value, label.confidence)

classifier = PTRClassifier()  # engine="re" (the default) or engine="hyperscan"
result = classifier.classify(
    "101.228.147.188.in-addr.arpa. PTR 188.147.228.101.nat.umts.dynamic.t-mobile.pl."
)
print(result.values())
print(result.to_dict())
```

Expected high-confidence labels include:

```text
ptrclassify:allocation="dynamic"
ptrclassify:access="mobile"
ptrclassify:translation="nat"
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

## Benchmark

After installing the optional dependency, compare steady-state lookup time on
the bundled sample data with:

```bash
python benchmarks/lookup.py
```

Use `--iterations`, `--repeat`, or `--file` to change the workload. Classifier
construction is deliberately excluded from the timed section so the result
measures lookup throughput rather than one-time expression compilation.

## Design notes

The design follows the same general idea used by Internet-topology work such as CAIDA Hoiho: operator naming conventions can be mined as evidence, but should be treated as inference rather than truth. This package focuses on usage/allocation/service classes instead of primarily extracting router geolocation.

Provider-specific rules are intentionally separated from generic tokens. This avoids dangerous inferences such as classifying every `softbank...` hostname as mobile simply because SoftBank also operates mobile networks.

For production enrichment, PTR classification is best combined with ASN/RDAP, BGP prefix data, geofeeds, known cloud/hosting prefixes, forward-confirmed reverse DNS (FCrDNS), and active/service observations.

## References / prior art

- RFC 8501, *Reverse DNS in IPv6 for Internet Service Providers*: discusses static, dynamic and dynamically generated reverse names and warns against over-interpreting PTR data.
- CAIDA Hoiho / ITDK: learns operator-specific regular expressions from router hostnames for infrastructure/geolocation inference; this project borrows the explainable-regex philosophy for a different taxonomy.
- AWS EC2 public hostname documentation: documents the `ec2-A-B-C-D.<region>.compute.amazonaws.com` form used by the provider-specific rules.

The classifier emits labels in MISP machine-tag form (`ptrclassify:predicate="value"`). A MISP taxonomy definition suitable for validation or import is provided in `misp-taxonomy/machinetag.json`.

The built-in taxonomy is not claimed to be an Internet standard. It is designed as a practical, extensible CTI/network-enrichment taxonomy with orthogonal namespaces instead of a single mutually-exclusive class.
