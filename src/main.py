import sys
import os
import argparse

# allow imports from src/
sys.path.insert(0, os.path.dirname(__file__))

from parser import parse
from taint import analyze
from python_analyzer import analyze_python
from reporter import print_report
from policy import Policy


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="taint-lite",
        description="Privacy taint analysis for IMP-Core (.imp) and Python (.py) programs.",
    )
    p.add_argument("file", help="Source file to analyze (.imp or .py)")
    p.add_argument(
        "--policy",
        metavar="POLICY.json",
        default=None,
        help=(
            "Path to a JSON policy file that extends the built-in sources/sinks. "
            "See examples/custom_policy.json for the schema."
        ),
    )
    return p


def main() -> None:
    args = build_parser().parse_args()
    path: str = args.file

    try:
        with open(path) as f:
            source = f.read()
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)

    # Load policy (built-in defaults, optionally extended by --policy file)
    if args.policy:
        try:
            policy = Policy.load(args.policy)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Error loading policy file: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        policy = Policy.default()

    # Dispatch to the right frontend based on file extension
    ext = os.path.splitext(path)[1].lower()
    if ext == ".py":
        try:
            leaks = analyze_python(source, policy)
        except SyntaxError as exc:
            print(f"Parse error: {exc}", file=sys.stderr)
            sys.exit(1)
    elif ext == ".imp":
        try:
            program = parse(source)
        except SyntaxError as exc:
            print(f"Parse error: {exc}", file=sys.stderr)
            sys.exit(1)
        leaks = analyze(program, policy)
    else:
        print(
            f"Error: unsupported file type '{ext}'. Use .imp or .py",
            file=sys.stderr,
        )
        sys.exit(1)

    print_report(leaks)
    if leaks:
        sys.exit(1)


if __name__ == "__main__":
    main()
