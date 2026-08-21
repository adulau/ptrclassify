from __future__ import annotations

import argparse
import json
import sys

from .classifier import PTRClassifier


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Classify reverse-DNS PTR hostnames using explainable heuristics")
    parser.add_argument("ptr", nargs="*", help="PTR hostname(s) or complete DNS PTR record line(s)")
    parser.add_argument("-f", "--file", help="Read one PTR/DNS record per line ('-' for stdin)")
    parser.add_argument("--json", action="store_true", help="Output one JSON object per input")
    parser.add_argument("--min-confidence", type=float, default=0.0, help="Only show labels at or above this confidence")
    parser.add_argument("--values-only", action="store_true", help="Print only MISP machine-tag values")
    parser.add_argument(
        "--engine", choices=("re", "hyperscan"), default="re",
        help="Regular-expression engine (default: re)",
    )
    return parser


def _inputs(args: argparse.Namespace):
    yield from args.ptr
    if args.file:
        stream = sys.stdin if args.file == "-" else open(args.file, encoding="utf-8")
        try:
            for line in stream:
                line = line.strip()
                if line and not line.startswith("#"):
                    yield line
        finally:
            if stream is not sys.stdin:
                stream.close()
    elif not args.ptr and not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if line:
                yield line


def main() -> int:
    args = build_parser().parse_args()
    try:
        classifier = PTRClassifier(engine=args.engine)
    except RuntimeError as exc:
        build_parser().error(str(exc))

    for raw in _inputs(args):
        result = classifier.classify(raw)
        result.labels = [label for label in result.labels if label.confidence >= args.min_confidence]
        if args.json:
            print(json.dumps(result.to_dict(), sort_keys=True))
        elif args.values_only:
            print("\t".join(result.values()))
        else:
            print(f"{raw}")
            if result.address:
                print(f"  IP:       {result.address}")
            print(f"  hostname: {result.hostname or '-'}")
            if result.hints:
                print(f"  hints:    {json.dumps(result.hints, sort_keys=True)}")
            if not result.labels:
                print("  labels:   (none)")
            else:
                print("  labels:")
                for label in result.labels:
                    ev = ", ".join(label.evidence)
                    print(f"    - {label.value:<32} {label.confidence:.2f}  [{ev}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
