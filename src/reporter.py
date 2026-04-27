from typing import List
from taint import Leak


def format_report(leaks: List[Leak]) -> str:
    if not leaks:
        return "No PII leaks detected."

    lines = []
    for leak in leaks:
        pii_sorted = ", ".join(sorted(leak.pii_types))
        lines.append(f"PII LEAK at line {leak.line}")
        lines.append(f"  Sink: {leak.sink}")
        lines.append(f"  PII types exposed: {{{pii_sorted}}}")
        lines.append(f"  Recommendation: {leak.recommendation}")
        lines.append("")
    return "\n".join(lines).rstrip()


def print_report(leaks: List[Leak]) -> None:
    print(format_report(leaks))
