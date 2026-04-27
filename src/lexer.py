import re
from dataclasses import dataclass
from typing import List


# Token types
IDENT   = "IDENT"
ASSIGN  = "ASSIGN"    # :=
LPAREN  = "LPAREN"    # (
RPAREN  = "RPAREN"    # )
COMMA   = "COMMA"     # ,
PLUS    = "PLUS"      # +
STRING  = "STRING"    # "..." or '...'
NEWLINE = "NEWLINE"
EOF     = "EOF"


@dataclass
class Token:
    type: str
    value: str
    line: int


_TOKEN_PATTERNS = [
    (ASSIGN,  r":="),
    (LPAREN,  r"\("),
    (RPAREN,  r"\)"),
    (COMMA,   r","),
    (PLUS,    r"\+"),
    (STRING,  r'"[^"]*"|\'[^\']*\''),
    (IDENT,   r"[A-Za-z_][A-Za-z0-9_]*"),
    (NEWLINE, r"\n"),
    ("SKIP",  r"[ \t]+"),
    ("COMMENT", r"#[^\n]*"),
]

_MASTER_RE = re.compile(
    "|".join(f"(?P<{name.replace('-', '_')}_{i}>{pat})"
             for i, (name, pat) in enumerate(_TOKEN_PATTERNS))
)

# Rebuild with cleaner group names
_RULES = [(name, re.compile(pat)) for name, pat in _TOKEN_PATTERNS]


def tokenize(source: str) -> List[Token]:
    tokens: List[Token] = []
    line = 1
    pos = 0
    while pos < len(source):
        matched = False
        for tok_type, pattern in _RULES:
            m = pattern.match(source, pos)
            if m:
                text = m.group(0)
                if tok_type == "SKIP":
                    pass
                elif tok_type == "COMMENT":
                    pass
                elif tok_type == NEWLINE:
                    tokens.append(Token(NEWLINE, text, line))
                    line += 1
                else:
                    tokens.append(Token(tok_type, text, line))
                pos = m.end()
                matched = True
                break
        if not matched:
            raise SyntaxError(f"Unexpected character {source[pos]!r} at line {line}")
    tokens.append(Token(EOF, "", line))
    return tokens
