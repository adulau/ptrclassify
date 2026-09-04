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

Or install the published package from PyPI:

```bash
python -m pip install ptrclassify
```

For development:

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

## API service

Install the API dependencies and start the FastAPI service:

```bash
python -m pip install '.[api]'
ptrclassify-api
```

The interactive Swagger UI is available at `http://localhost:8000/docs`, and
FastAPI serves the OpenAPI document at `http://localhost:8000/openapi.json`.
The same document is checked into this repository as [`openapi.json`](openapi.json).

Classify one or more hostnames or complete PTR record lines in one request:

```bash
curl -X POST http://localhost:8000/lookup \
  -H 'content-type: application/json' \
  -d '{"records":["ec2-3-151-166-120.us-east-2.compute.amazonaws.com.","188.147.228.101.nat.umts.dynamic.t-mobile.pl."]}'
```

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
for location in result.locations:
    print(location.city, location.region, location.country, location.confidence)
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

### CSV enrichment

To classify every value in a CSV column named `ptr`, use the CSV enrichment
script. It preserves the existing columns and appends a `ptrclassify` column
containing the complete classification as compact JSON:

```bash
ptrclassify-csv input.csv output.csv
# Or, without installing the command:
python classify_ptr_csv.py input.csv output.csv
```

Use `-` (or omit both paths) to read from standard input or write to standard
output. Alternate column names can be selected with `--ptr-field` and
`--output-field`:

```bash
ptrclassify-csv --ptr-field hostname --output-field classification input.csv output.csv
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

## Potential location extraction

The classifier can also decode a conservative set of operator-specific
geographic tokens.  Candidates are separate from taxonomy labels because a
place is open-ended data rather than a classification category:

```python
result = PTRClassifier().classify("pool-74-96-220-47.washdc.fios.verizon.net")
print(result.locations[0].to_dict())
# {'code': 'washdc', 'city': 'Washington', ..., 'confidence': 0.9}
```

Each candidate includes the original code, matched evidence, confidence and
rule ID as well as any decoded city, region and ISO 3166-1 alpha-2 country.
Hostnames ending in an ISO country-code TLD (for example, `.pl` or `.de`) also
produce a lower-confidence country candidate.  A country-code TLD reflects the
DNS namespace and does not guarantee that the named host is physically in that
country; generic TLDs such as `.com` and `.net` do not produce this hint.
Built-in templates live in `ptrclassify/data/location_rules.json`.  They are
deliberately scoped to an operator suffix: a token such as `ord56` on an
unrelated domain is not treated as Chicago.  Private conventions can be added
with `extra_location_rules`:

The built-in infrastructure templates include AWS EC2 region names, Azure
`cloudapp.azure.com` regions, and a curated set of Amazon CloudFront POP codes.
These complement the access-network templates and make the location candidate
useful for CDN and datacenter PTRs without treating generic IATA-like labels as
locations.

```python
classifier = PTRClassifier(extra_location_rules=[{
    "id": "location.example.site",
    "confidence": 0.95,
    "pattern": r"\.(?P<code>hq)\.example\.net$",
    "locations": {"hq": {"city": "Example City", "country": "ZZ"}},
}])
```

This follows the explainable, domain-specific rule strategy used by hostname
geolocation systems: extract tokens in the context of a network's naming
convention, then resolve them through a curated code dictionary.  Backbone router templates for Hurricane Electric and Cogent apply
the same approach to operator-scoped POP codes (for example, `lax2` and
`lax01`).  A candidate
describes where the operator says the named device or service belongs; it must
not be interpreted as the subscriber's exact location or as a measurement.

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
- [IETF IP Geolocation Workshop materials](https://datatracker.ietf.org/group/ipgeows/materials/): workshop context for treating network-provided location signals as scoped, fallible hints rather than ground truth.
- [CAIDA Hoiho](https://www.caida.org/catalog/software/hoiho/) / ITDK: learns operator-specific regular expressions from router hostnames for infrastructure/geolocation inference; this project borrows its explainable-regex philosophy.
- [DRoP](https://doi.org/10.1145/2398776.2398790), *DNS-based Router Positioning*: prior work on extracting and validating router location hints from hostnames.
- AWS EC2 public hostname documentation: documents the `ec2-A-B-C-D.<region>.compute.amazonaws.com` form used by the provider-specific rules.

The classifier emits labels in MISP machine-tag form (`ptrclassify:predicate="value"`). A MISP taxonomy definition suitable for validation or import is provided in `misp-taxonomy/machinetag.json` and
[officially published as a MISP taxonomy](https://misp-project.org/taxonomies.html#_ptrclassify).

The built-in taxonomy is not claimed to be an Internet standard. It is designed as a practical, extensible CTI/network-enrichment taxonomy with orthogonal namespaces instead of a single mutually-exclusive class.

## Publishing

Releases are published by the `Publish to PyPI` GitHub Actions workflow. Before
the first release, configure a [PyPI trusted publisher](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)
for this repository with workflow name `publish.yml` and environment name
`pypi`; no long-lived PyPI API token is required.

To publish a new version, update `project.version` in `pyproject.toml`, merge the
change, and publish a GitHub release. The workflow builds both the source and
wheel distributions, validates them, and publishes them to the `ptrclassify`
PyPI project. It can also be started manually from the Actions tab when a
release job needs to be retried.
