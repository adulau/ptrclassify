"""CSV enrichment command for PTR classification results."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from contextlib import ExitStack
from typing import TextIO

from .classifier import PTRClassifier


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Read a CSV file and append the ptrclassify result for each value "
            "in its 'ptr' column."
        )
    )
    parser.add_argument("input", nargs="?", default="-", help="Input CSV file (default: stdin)")
    parser.add_argument("output", nargs="?", default="-", help="Output CSV file (default: stdout)")
    parser.add_argument(
        "--ptr-field", default="ptr", help="Column containing PTR records (default: ptr)"
    )
    parser.add_argument(
        "--output-field",
        default="ptrclassify",
        help="Column to add with the JSON classification (default: ptrclassify)",
    )
    parser.add_argument(
        "--labels-field",
        default="ptrclassify_labels",
        help=(
            "Column to add with a compact JSON array of label values "
            "(default: ptrclassify_labels)"
        ),
    )
    parser.add_argument(
        "--engine",
        choices=("re", "hyperscan"),
        default="re",
        help="Regular-expression engine (default: re)",
    )
    return parser


def enrich_csv(
    source: TextIO,
    destination: TextIO,
    classifier: PTRClassifier,
    ptr_field: str = "ptr",
    output_field: str = "ptrclassify",
    labels_field: str = "ptrclassify_labels",
) -> None:
    """Copy rows while appending compact labels and the full classification."""
    reader = csv.DictReader(source)
    if reader.fieldnames is None:
        raise ValueError("input CSV is missing a header row")
    if ptr_field not in reader.fieldnames:
        raise ValueError(f"input CSV is missing required field {ptr_field!r}")
    if output_field in reader.fieldnames:
        raise ValueError(f"input CSV already contains output field {output_field!r}")
    if labels_field in reader.fieldnames:
        raise ValueError(f"input CSV already contains labels field {labels_field!r}")
    if labels_field == output_field:
        raise ValueError("labels field and output field must be different")

    writer = csv.DictWriter(
        destination,
        fieldnames=[*reader.fieldnames, labels_field, output_field],
    )
    writer.writeheader()
    for row in reader:
        classification = classifier.classify(row[ptr_field] or "")
        row[labels_field] = json.dumps(
            classification.values(),
            separators=(",", ":"),
        )
        row[output_field] = json.dumps(
            classification.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )
        writer.writerow(row)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        classifier = PTRClassifier(engine=args.engine)
    except RuntimeError as exc:
        parser.error(str(exc))

    try:
        with ExitStack() as stack:
            source = (
                sys.stdin
                if args.input == "-"
                else stack.enter_context(open(args.input, newline="", encoding="utf-8-sig"))
            )
            destination = (
                sys.stdout
                if args.output == "-"
                else stack.enter_context(open(args.output, "w", newline="", encoding="utf-8"))
            )
            enrich_csv(
                source,
                destination,
                classifier,
                ptr_field=args.ptr_field,
                output_field=args.output_field,
                labels_field=args.labels_field,
            )
    except (OSError, csv.Error, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
