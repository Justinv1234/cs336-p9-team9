import sys
import os

# allow imports from src/
sys.path.insert(0, os.path.dirname(__file__))

from parser import parse
from taint import analyze
from reporter import print_report


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <program.imp>", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]
    try:
        with open(path) as f:
            source = f.read()
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)

    program = parse(source)
    leaks = analyze(program)
    print_report(leaks)

    if leaks:
        sys.exit(1)


if __name__ == "__main__":
    main()
