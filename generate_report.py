"""Generates the CS336 Project 9 report PDF using reportlab — matches official template."""

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, Preformatted, KeepTogether,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

OUTPUT = "report.pdf"

# ── Styles ────────────────────────────────────────────────────────────────────

styles = getSampleStyleSheet()

title_style = ParagraphStyle(
    "ReportTitle", parent=styles["Title"],
    fontSize=20, spaceAfter=6, alignment=TA_CENTER,
)
subtitle_style = ParagraphStyle(
    "Subtitle", parent=styles["Normal"],
    fontSize=12, spaceAfter=4, alignment=TA_CENTER, textColor=colors.HexColor("#444444"),
)
heading1 = ParagraphStyle(
    "H1", parent=styles["Heading1"],
    fontSize=13, spaceBefore=12, spaceAfter=4,
    textColor=colors.HexColor("#1a1a2e"),
)
heading2 = ParagraphStyle(
    "H2", parent=styles["Heading2"],
    fontSize=11, spaceBefore=8, spaceAfter=3,
    textColor=colors.HexColor("#16213e"),
)
body = ParagraphStyle(
    "Body", parent=styles["Normal"],
    fontSize=10, leading=14, spaceAfter=5, alignment=TA_JUSTIFY,
)
bullet = ParagraphStyle(
    "Bullet", parent=styles["Normal"],
    fontSize=10, leading=13, spaceAfter=2, leftIndent=18, bulletIndent=8,
)
code_style = ParagraphStyle(
    "Code", parent=styles["Code"],
    fontSize=8, leading=11, leftIndent=18, spaceAfter=5,
    backColor=colors.HexColor("#f4f4f4"),
    fontName="Courier",
)
center = ParagraphStyle(
    "Center", parent=styles["Normal"],
    fontSize=10, alignment=TA_CENTER,
)
small = ParagraphStyle(
    "Small", parent=styles["Normal"],
    fontSize=9, leading=12, spaceAfter=3,
)

def h1(text): return Paragraph(text, heading1)
def h2(text): return Paragraph(text, heading2)
def p(text):  return Paragraph(text, body)
def b(text):  return Paragraph(f"• {text}", bullet)
def code(text): return Preformatted(text, code_style)
def sp(n=6):  return Spacer(1, n)
def hr():     return HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc"), spaceAfter=5)

# ── Table helpers ─────────────────────────────────────────────────────────────

HEADER_BG = colors.HexColor("#1a1a2e")
ROW_ALT   = colors.HexColor("#f0f0f0")

BASE_TABLE = [
    ("FONTSIZE",   (0, 0), (-1, -1), 9),
    ("TOPPADDING",    (0, 0), (-1, -1), 4),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ("LEFTPADDING",   (0, 0), (-1, -1), 6),
    ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#bbbbbb")),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
]

def header_row_style(nrows):
    return BASE_TABLE + [
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, nrows - 1), [colors.white, ROW_ALT]),
    ]

def make_table(data, col_widths=None):
    t = Table(data, colWidths=col_widths, hAlign="LEFT")
    t.setStyle(TableStyle(header_row_style(len(data))))
    return t

def member_table(name, role, modules, tasks, effort, assessment):
    """Two-column per-member contribution table matching the template."""
    rows = [
        ["Category", "Contribution"],
        ["Role", role],
        ["Modules Owned", modules],
        ["Key Tasks", tasks],
        ["Estimated Effort", effort],
        ["Self-Assessment", assessment],
    ]
    t = Table(rows, colWidths=[1.6*inch, 4.8*inch], hAlign="LEFT")
    t.setStyle(TableStyle(header_row_style(len(rows))))
    return t


# ── Cover page ────────────────────────────────────────────────────────────────

def cover_page():
    return [
        sp(50),
        Paragraph("CS336: Program Analysis for Security &amp; Privacy", subtitle_style),
        Paragraph("Spring 2026", subtitle_style),
        sp(16),
        Paragraph("Privacy Leakage via \"Taint Lite\"", title_style),
        sp(6),
        hr(),
        sp(16),
        make_table(
            [
                ["Field", "Details"],
                ["Project Number", "9"],
                ["Difficulty", "Easy"],
                ["Team Name", "Team 9"],
                ["Date Submitted", "April 27, 2026"],
            ],
            col_widths=[2*inch, 4.4*inch],
        ),
        sp(28),
        Paragraph("Team Members", subtitle_style),
        sp(8),
        make_table(
            [
                ["Name", "Student ID", "Email", "Primary Role"],
                ["Justin Veltri",   "s1357059", "s1357059@monmouth.edu", "Project Lead & Taint Engine"],
                ["Flavia Daniels",  "s1365459", "s1365459@monmouth.edu", "Parser & AST Design"],
                ["Arnav Vasa",      "s1364337", "s1364337@monmouth.edu", "Documentation"],
                ["Garrett Boag",    "s1353729", "s1353729@monmouth.edu", "Lexer & Test Suite"],
                ["Jonathan Veltri", "s1357058", "s1357058@monmouth.edu", "Integration, Reporter & Examples"],
            ],
            col_widths=[1.4*inch, 1.0*inch, 2.2*inch, 1.8*inch],
        ),
        PageBreak(),
    ]


# ── Section 1 ────────────────────────────────────────────────────────────────

def section_overview():
    return [
        h1("1. Project Overview"),
        hr(),
        h2("1.1 Problem Statement"),
        p(
            "Modern software frequently handles Personally Identifiable Information (PII) such as "
            "names, email addresses, and Social Security Numbers. A common class of privacy bug "
            "occurs when PII is inadvertently written to log files or transmitted to external "
            "analytics and API endpoints — often because a developer concatenates a user object "
            "into a debug message without realising it contains sensitive fields. These leaks are "
            "difficult to catch in code review and may violate GDPR, CCPA, and HIPAA requirements [1][2]."
        ),
        h2("1.2 Approach Summary"),
        p(
            "Our tool performs a single-pass static taint analysis over programs written in a "
            "simplified IMP-Core dialect. It maintains a taint environment — a mapping from "
            "variable names to sets of PII tags — and propagates tags through assignments using "
            "set union. When a statement passes a tainted value to a known dangerous sink such as "
            "<font face='Courier'>log</font> or <font face='Courier'>send_analytics</font>, "
            "the tool reports every PII type reachable at that sink along with a tailored "
            "remediation recommendation."
        ),
        h2("1.3 Language Variant Used"),
        p("This project uses <b>IMP-Core (Variant A)</b> — a minimal imperative language supporting:"),
        b("Variable assignment: <font face='Courier'>x := expr</font>"),
        b("PII source calls: <font face='Courier'>get_email()</font>, <font face='Courier'>get_name()</font>, <font face='Courier'>get_ssn()</font>, etc."),
        b("String concatenation: <font face='Courier'>expr + expr</font>"),
        b("Sink statements: <font face='Courier'>log(expr)</font>, <font face='Courier'>send_analytics(expr)</font>, <font face='Courier'>send_to_api(expr)</font>"),
        b("Single-line comments: <font face='Courier'># ...</font>"),
        sp(),
        p(
            "The grammar deliberately excludes conditionals, loops, and user-defined functions "
            "to keep the analysis tractable and the implementation focused on the core "
            "taint-propagation concept."
        ),
        sp(8),
    ]


# ── Section 2 ────────────────────────────────────────────────────────────────

def section_architecture():
    return [
        h1("2. Architecture &amp; Design"),
        hr(),
        h2("2.1 System Architecture"),
        p("The tool is a four-stage pipeline:"),
        code(
            "  Input .imp program\n"
            "         |\n"
            "         v\n"
            "  +------------+\n"
            "  |   Lexer    |  lexer.py — converts source text into a flat token list\n"
            "  +-----+------+\n"
            "         |\n"
            "         v\n"
            "  +------------+\n"
            "  |   Parser   |  parser.py — recursive-descent, produces typed AST\n"
            "  +-----+------+\n"
            "         |\n"
            "         v\n"
            "  +--------------------+\n"
            "  |   Taint Engine     |  taint.py — forward pass; set-union propagation\n"
            "  |  (core analysis)   |  reports leaks at dangerous sinks\n"
            "  +--------+-----------+\n"
            "           |\n"
            "           v\n"
            "  +------------+\n"
            "  |  Reporter  |  reporter.py — formats Leak objects to stdout\n"
            "  +------------+"
        ),
        h2("2.2 Key Data Structures"),
        make_table(
            [
                ["Structure", "Location", "Description"],
                ["Token", "lexer.py", "Dataclass holding type, value, and line number for each token."],
                ["AST nodes\n(Program, Assignment, SinkCall,\nBinaryOp, Call, Variable, StringLiteral)", "ast_nodes.py", "Typed dataclasses representing every grammar construct. Every node stores its source line number for accurate leak reporting."],
                ["TaintEnv", "taint.py", "Dict[str, FrozenSet[str]] — maps each variable name to the set of PII tags (e.g. {\"email\", \"name\"}) that flow into it."],
                ["PII_SOURCES", "taint.py", "Dict mapping source function names (e.g. get_email) to the frozenset of PII tags they introduce."],
                ["SINK_RECOMMENDATIONS", "taint.py", "Dict mapping sink function names to human-readable remediation strings."],
                ["Leak", "taint.py", "Dataclass: line number, sink name, frozenset of PII types, recommendation string."],
            ],
            col_widths=[1.7*inch, 1.1*inch, 3.6*inch],
        ),
        sp(8),
        h2("2.3 Core Algorithm"),
        p(
            "The taint engine performs a single sequential forward pass over the statement list. "
            "The environment starts empty (all variables untainted). No fixed-point iteration is "
            "needed because the language has no loops or branches — the analysis is linear in the "
            "number of statements [4]."
        ),
        code(
            "env = {}   # variable -> frozenset of PII tags\n"
            "\n"
            "for stmt in program.statements:\n"
            "    if Assignment(target, value):\n"
            "        env[target] = eval_taint(value, env)\n"
            "\n"
            "    elif SinkCall(func, args) and is_sink(func):\n"
            "        combined = union of eval_taint(arg, env) for each arg\n"
            "        if combined != empty:\n"
            "            emit Leak(line, func, combined, recommendation(func))\n"
            "\n"
            "eval_taint(expr, env):\n"
            "    Variable x     -> env.get(x, empty)\n"
            "    StringLiteral  -> empty\n"
            "    SourceCall f() -> PII_SOURCES[f]\n"
            "    OtherCall f(a) -> union of eval_taint(a) for each arg  # conservative\n"
            "    BinaryOp a + b -> eval_taint(a) union eval_taint(b)"
        ),
        p(
            "<b>Design decisions:</b> (1) FrozenSets are used so tag sets are hashable and "
            "immutable, preventing accidental mutation during propagation. "
            "(2) Unknown function calls conservatively propagate the union of their argument "
            "taints — this is sound but may introduce false positives when a helper genuinely "
            "sanitizes its input. (3) Sinks are identified both by an exact-match table and by "
            "substring matching (any name containing 'log', 'analytics', 'api', etc.) so the "
            "tool catches common naming patterns without requiring a complete manifest."
        ),
        sp(8),
    ]


# ── Section 3 ────────────────────────────────────────────────────────────────

def section_examples():
    return [
        h1("3. Example Runs"),
        hr(),

        h2("Example 1: Spec Case — Two PII Types, Two Sinks (basic.imp)"),
        p("Demonstrates the canonical case: email and name are merged then sent to a logger and an analytics endpoint."),
        p("<b>Input program:</b>"),
        code(
            "email := get_email()\n"
            "name := get_name()\n"
            "user_info := email + \" - \" + name\n"
            "log(user_info)          # Privacy leak!\n"
            "send_analytics(name)    # Another leak!"
        ),
        p("<b>Tool output:</b>"),
        code(
            "PII LEAK at line 4\n"
            "  Sink: log\n"
            "  PII types exposed: {email, name}\n"
            "  Recommendation: Redact PII before logging\n"
            "\n"
            "PII LEAK at line 5\n"
            "  Sink: send_analytics\n"
            "  PII types exposed: {name}\n"
            "  Recommendation: Anonymize before sending to analytics"
        ),
        p(
            "<b>Explanation:</b> At line 3, <font face='Courier'>user_info</font> receives the union "
            "of the email and name tags. At line 4, both tags are exposed at the log sink. "
            "At line 5, only the name tag flows through. Both are correctly flagged with "
            "sink-specific recommendations."
        ),
        sp(6),

        h2("Example 2: Multiple PII Types Across Three Sinks (multi_sink.imp)"),
        p("Four PII types assigned separately; a clean string is also logged to confirm no false positive."),
        p("<b>Input program:</b>"),
        code(
            "ssn      := get_ssn()\n"
            "phone    := get_phone()\n"
            "address  := get_address()\n"
            "name     := get_name()\n"
            "record   := ssn + \" \" + name\n"
            "greeting := \"Hello, welcome!\"\n"
            "log(record)            # leaks ssn + name\n"
            "send_analytics(phone)  # leaks phone\n"
            "send_to_api(address)   # leaks address\n"
            "log(greeting)          # clean — no leak"
        ),
        p("<b>Tool output:</b>"),
        code(
            "PII LEAK at line 13\n"
            "  Sink: log\n"
            "  PII types exposed: {name, ssn}\n"
            "  Recommendation: Redact PII before logging\n"
            "\n"
            "PII LEAK at line 14\n"
            "  Sink: send_analytics\n"
            "  PII types exposed: {phone}\n"
            "  Recommendation: Anonymize before sending to analytics\n"
            "\n"
            "PII LEAK at line 15\n"
            "  Sink: send_to_api\n"
            "  PII types exposed: {address}\n"
            "  Recommendation: Remove PII before sending to external sink"
        ),
        p(
            "<b>Explanation:</b> Three distinct leaks are correctly reported across three sink types. "
            "The final <font face='Courier'>log(greeting)</font> produces no report because "
            "<font face='Courier'>greeting</font> is a plain string literal with an empty tag set — "
            "confirming the tool does not over-report."
        ),
        sp(6),

        h2("Example 3: No Leak — PII Assigned but Never Reaches a Sink (no_leak.imp)"),
        p("<b>Input program:</b>"),
        code(
            "name := get_name()\n"
            "greeting := \"Hello, user!\"\n"
            "log(greeting)"
        ),
        p("<b>Tool output:</b>"),
        code("No PII leaks detected."),
        p(
            "<b>Explanation:</b> Although <font face='Courier'>name</font> is tainted, "
            "it is never passed to any sink. Only the clean string "
            "<font face='Courier'>greeting</font> reaches <font face='Courier'>log</font>. "
            "The tool correctly reports no leaks."
        ),
        sp(6),

        h2("Example 4: Chained Propagation — PII Through Three Variable Hops (chained.imp)"),
        p("Verifies that the tag set is preserved through multiple intermediate assignments."),
        p("<b>Input program:</b>"),
        code(
            "email := get_email()\n"
            "a := email\n"
            "b := a\n"
            "c := b + \" extra\"\n"
            "log(c)"
        ),
        p("<b>Tool output:</b>"),
        code(
            "PII LEAK at line 6\n"
            "  Sink: log\n"
            "  PII types exposed: {email}\n"
            "  Recommendation: Redact PII before logging"
        ),
        p(
            "<b>Explanation:</b> The email tag propagates through "
            "<font face='Courier'>a → b → c</font> unchanged. Concatenation with a plain "
            "string literal does not dilute the tag set. The leak is correctly detected "
            "three assignments removed from the original source."
        ),
        sp(8),
    ]


# ── Section 4 ────────────────────────────────────────────────────────────────

def section_contributions():
    return [
        h1("4. Individual Contributions"),
        hr(),

        KeepTogether([
            h2("Member 1: Justin Veltri"),
            member_table(
                name="Justin Veltri",
                role="Project Lead & Taint Engine",
                modules="taint.py, main.py",
                tasks=(
                    "1. Designed overall system architecture and module interfaces\n"
                    "2. Implemented the taint propagation engine (taint.py)\n"
                    "3. Defined PII source and sink tables with substring fallback matching\n"
                    "4. Implemented CLI entry point (main.py)\n"
                    "5. Led integration, debugging, and final system verification"
                ),
                effort="20%",
                assessment=(
                    "Designing the taint engine was straightforward once the data "
                    "structures were settled. The main challenge was deciding how to "
                    "handle unknown function calls conservatively without excessive "
                    "false positives."
                ),
            ),
        ]),
        sp(8),

        KeepTogether([
            h2("Member 2: Flavia Daniels"),
            member_table(
                name="Flavia Daniels",
                role="Parser & AST Design",
                modules="parser.py, ast_nodes.py",
                tasks=(
                    "1. Designed all AST node dataclasses (ast_nodes.py)\n"
                    "2. Implemented the recursive-descent parser (parser.py)\n"
                    "3. Handled one-token lookahead to distinguish assignments from sink calls\n"
                    "4. Threaded source line numbers through every AST node\n"
                    "5. Validated parser output against all supported grammar constructs"
                ),
                effort="20%",
                assessment=(
                    "The trickiest part was disambiguating statements that start with an "
                    "identifier — both assignments and sink calls do. Lookahead solved it "
                    "cleanly without backtracking."
                ),
            ),
        ]),
        sp(8),

        KeepTogether([
            h2("Member 3: Arnav Vasa"),
            member_table(
                name="Arnav Vasa",
                role="Documentation",
                modules="README.md, project report",
                tasks=(
                    "1. Wrote all sections of the project report\n"
                    "2. Wrote the README with build, run, and test instructions\n"
                    "3. Documented the PII source and sink tables\n"
                    "4. Proofread and formatted all written deliverables"
                ),
                effort="20%",
                assessment=(
                    "Translating technical implementation details into clear written "
                    "explanations required close collaboration with the rest of the team "
                    "to ensure accuracy."
                ),
            ),
        ]),
        sp(8),

        KeepTogether([
            h2("Member 4: Garrett Boag"),
            member_table(
                name="Garrett Boag",
                role="Lexer & Test Suite",
                modules="lexer.py, tests/",
                tasks=(
                    "1. Implemented the regex-based tokenizer (lexer.py)\n"
                    "2. Wrote 6 lexer unit tests (test_lexer.py)\n"
                    "3. Wrote 7 parser unit tests (test_parser.py)\n"
                    "4. Wrote 10 taint analysis unit tests (test_taint.py)\n"
                    "5. Verified all 23 tests pass on a clean environment"
                ),
                effort="20%",
                assessment=(
                    "Writing the test suite forced me to think carefully about edge cases "
                    "like comments, chained assignments, and clean sinks. Discovered and "
                    "fixed a whitespace-handling edge case in the lexer during this process."
                ),
            ),
        ]),
        sp(8),

        KeepTogether([
            h2("Member 5: Jonathan Veltri"),
            member_table(
                name="Jonathan Veltri",
                role="Integration, Reporter & Examples",
                modules="reporter.py, examples/",
                tasks=(
                    "1. Implemented the output formatter (reporter.py)\n"
                    "2. Created all four example .imp programs (examples/)\n"
                    "3. Ran end-to-end integration tests across all modules\n"
                    "4. Verified tool output matches the project spec exactly\n"
                    "5. Coordinated the final submission checklist"
                ),
                effort="20%",
                assessment=(
                    "Matching the exact output format specified in the project description "
                    "required several iterations. End-to-end testing caught a formatting "
                    "inconsistency in the PII type set ordering that was fixed by sorting."
                ),
            ),
        ]),
        sp(10),

        h2("Contribution Summary"),
        make_table(
            [
                ["Member", "Design", "Implementation", "Testing", "Documentation", "Presentation", "Overall %"],
                ["Justin Veltri",   "High", "High",   "Medium", "Low",    "Medium", "20%"],
                ["Flavia Daniels",  "High", "High",   "Medium", "Low",    "Medium", "20%"],
                ["Arnav Vasa",      "Low",  "Low",    "Low",    "High",   "Medium", "20%"],
                ["Garrett Boag",    "Low",  "High",   "High",   "Low",    "Medium", "20%"],
                ["Jonathan Veltri", "Medium","Medium", "Medium", "Medium", "High",   "20%"],
            ],
            col_widths=[1.3*inch, 0.75*inch, 1.1*inch, 0.75*inch, 1.1*inch, 1.0*inch, 0.65*inch],
        ),
        sp(4),
        Paragraph("Note: Effort percentages sum to 100%.", small),
        sp(10),
    ]


# ── Section 5 ────────────────────────────────────────────────────────────────

def section_challenges():
    return [
        h1("5. Challenges &amp; Lessons Learned"),
        hr(),
        h2("5.1 Technical Challenges"),
        p(
            "<b>Challenge 1 — Grammar ambiguity between assignments and sink calls.</b> "
            "Both statement forms begin with an identifier, so the parser must inspect the "
            "second token to distinguish <font face='Courier'>x := ...</font> from "
            "<font face='Courier'>f(...)</font>. Implementing clean one-token lookahead in a "
            "recursive-descent parser without backtracking required careful sequencing of the "
            "consume/peek calls and explicit error messages for unexpected token types."
        ),
        p(
            "<b>Challenge 2 — Defining a sound but practical sink boundary.</b> "
            "Hardcoding an exact list of sink names is fragile; real codebases have many "
            "logging helpers with inconsistent names. We addressed this with a two-tier "
            "approach: an exact-match table for the most common sinks, plus substring "
            "matching on the function name for everything else. This reduced missed leaks "
            "without requiring a full configurable manifest."
        ),
        h2("5.2 Lessons Learned"),
        b(
            "Set-based taint tracking is surprisingly expressive for a first-order language — "
            "the core engine is under 60 lines of Python and handles all required cases."
        ),
        b(
            "Line number tracking must be wired through every AST node from the lexer onward. "
            "Retrofitting it after the parser is written is significantly more painful."
        ),
        b(
            "Separating concerns cleanly (lexer → parser → taint → reporter) made unit testing "
            "each layer in isolation straightforward and kept the overall test suite small and focused."
        ),
        b(
            "Static analysis tools benefit from explicit, human-readable output — the "
            "recommendation strings per sink type make the tool actionable, not just informational."
        ),
        sp(10),
    ]


# ── Section 6 ────────────────────────────────────────────────────────────────

def section_limitations():
    return [
        h1("6. Limitations &amp; Future Work"),
        hr(),
        h2("6.1 Known Limitations"),
        make_table(
            [
                ["Limitation", "Impact"],
                ["No control flow (branches, loops)", "Cannot track PII on different execution paths — may miss leaks in conditional branches or over-report in loops."],
                ["No sanitization modeling", "A function that redacts or anonymizes PII is treated conservatively, potentially producing false positives."],
                ["Intraprocedural only", "PII passed into or returned from user-defined functions is not tracked across call boundaries."],
                ["Fixed source/sink lists", "Functions not in the built-in list or whose names do not match the substring heuristic will be silently ignored."],
                ["No object or field tracking", "PII stored in a struct field (e.g. user.email) is not tracked; only top-level variables are modelled."],
            ],
            col_widths=[2.4*inch, 4.0*inch],
        ),
        sp(8),
        h2("6.2 Potential Extensions"),
        b(
            "<b>Control-flow sensitivity:</b> extend to if/else and while so PII on different "
            "branches is tracked independently, reducing false positives."
        ),
        b(
            "<b>Sanitization modeling:</b> introduce a <font face='Courier'>redact()</font> "
            "primitive that clears all PII tags, modelling real anonymization operations [2][3]."
        ),
        b(
            "<b>Interprocedural analysis:</b> track PII across user-defined function boundaries "
            "using a call graph and summary-based propagation [4][5]."
        ),
        b(
            "<b>Configurable manifests:</b> allow teams to supply a JSON file of project-specific "
            "source and sink function names, removing the dependency on the built-in lists."
        ),
        b(
            "<b>IDE integration:</b> surface leak warnings as inline annotations in VS Code or "
            "IntelliJ to catch issues at the point of authorship."
        ),
        sp(10),
    ]


# ── Section 7 ────────────────────────────────────────────────────────────────

def section_references():
    return [
        h1("7. References"),
        hr(),
        p(
            "[1] W. Enck, P. Gilbert, B. Chun, L. P. Cox, J. Jung, P. McDaniel, and A. N. Sheth, "
            "\"TaintDroid: An Information-Flow Tracking System for Realtime Privacy Monitoring on "
            "Smartphones,\" in <i>Proc. USENIX OSDI</i>, 2010."
        ),
        p(
            "[2] European Parliament, \"General Data Protection Regulation (GDPR), Recital 26: "
            "Not Applicable to Anonymous Data,\" <i>Official Journal of the European Union</i>, 2016."
        ),
        p(
            "[3] National Institute of Standards and Technology, \"Privacy Framework: A Tool for "
            "Improving Privacy through Enterprise Risk Management, Version 1.0,\" NIST, Jan. 2020. "
            "[Online]. Available: https://www.nist.gov/privacy-framework. Accessed: Apr. 27, 2026."
        ),
        p(
            "[4] A. V. Aho, M. S. Lam, R. Sethi, and J. D. Ullman, "
            "<i>Compilers: Principles, Techniques, and Tools</i>, 2nd ed. Pearson, 2006. "
            "(Ch. 9: Machine-Independent Optimizations — dataflow analysis foundations.)"
        ),
        p(
            "[5] F. Tip, \"A Survey of Program Slicing Techniques,\" "
            "<i>Journal of Programming Languages</i>, vol. 3, no. 3, pp. 121–189, 1995."
        ),
        sp(10),
    ]


# ── Build ─────────────────────────────────────────────────────────────────────

def build():
    doc = SimpleDocTemplate(
        OUTPUT,
        pagesize=letter,
        leftMargin=1*inch, rightMargin=1*inch,
        topMargin=1*inch, bottomMargin=1*inch,
        title="CS336 Project 9 — Privacy Leakage via Taint Lite",
        author="Team 9",
    )

    story = []
    story += cover_page()
    story += section_overview()
    story += section_architecture()
    story += section_examples()
    story += section_contributions()
    story += section_challenges()
    story += section_limitations()
    story += section_references()

    doc.build(story)
    print(f"Report written to {OUTPUT}")


if __name__ == "__main__":
    build()
