#!/usr/bin/env python3
"""Compare steady-state PTR lookup time for re and Hyperscan."""

from __future__ import annotations

import argparse
from pathlib import Path
import statistics
import time

from ptrclassify import PTRClassifier


def benchmark(classifier: PTRClassifier, records: list[str], iterations: int, repeat: int) -> list[float]:
    timings = []
    for _ in range(repeat):
        started = time.perf_counter()
        for _ in range(iterations):
            for record in records:
                classifier.classify(record)
        timings.append(time.perf_counter() - started)
    return timings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, default=Path("tests/data/sample.ptr"))
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()
    if args.iterations < 1 or args.repeat < 1:
        parser.error("--iterations and --repeat must be positive")

    records = [line.strip() for line in args.file.read_text().splitlines() if line.strip()]
    if not records:
        parser.error("input file contains no records")

    engines = {}
    for engine in ("re", "hyperscan"):
        try:
            engines[engine] = PTRClassifier(engine=engine)
        except RuntimeError as exc:
            parser.error(str(exc))

    expected = [engines["re"].classify(record).to_dict() for record in records]
    actual = [engines["hyperscan"].classify(record).to_dict() for record in records]
    if actual != expected:
        raise RuntimeError("engines produced different classifications")

    lookups = len(records) * args.iterations
    medians = {}
    for engine, classifier in engines.items():
        elapsed = benchmark(classifier, records, args.iterations, args.repeat)
        medians[engine] = statistics.median(elapsed)
        print(f"{engine:9} {medians[engine]:.6f}s  {medians[engine] / lookups * 1e6:.2f} us/lookup")
    print(f"speedup   {medians['re'] / medians['hyperscan']:.2f}x")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
