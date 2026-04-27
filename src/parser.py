from typing import List
from lexer import Token, tokenize, IDENT, ASSIGN, LPAREN, RPAREN, COMMA, PLUS, STRING, NEWLINE, EOF
from ast_nodes import (
    Program, Assignment, SinkCall,
    Variable, StringLiteral, Call, BinaryOp, Expr, Statement,
)

# Functions that are dangerous sinks
SINKS = {
    "log",
    "send_analytics",
    "send_to_api",
    "print_log",
    "write_log",
    "post_to_server",
}


class Parser:
    def __init__(self, tokens: List[Token]):
        self._tokens = tokens
        self._pos = 0

    def _peek(self) -> Token:
        return self._tokens[self._pos]

    def _consume(self, expected_type: str = None) -> Token:
        tok = self._tokens[self._pos]
        if expected_type and tok.type != expected_type:
            raise SyntaxError(
                f"Line {tok.line}: expected {expected_type}, got {tok.type} ({tok.value!r})"
            )
        self._pos += 1
        return tok

    def _skip_newlines(self):
        while self._peek().type == NEWLINE:
            self._consume()

    def parse(self) -> Program:
        stmts: List[Statement] = []
        self._skip_newlines()
        while self._peek().type != EOF:
            stmt = self._parse_statement()
            if stmt is not None:
                stmts.append(stmt)
            self._skip_newlines()
        return Program(statements=stmts)

    def _parse_statement(self) -> Statement:
        tok = self._peek()
        if tok.type != IDENT:
            raise SyntaxError(f"Line {tok.line}: expected identifier, got {tok.type}")

        # look ahead to distinguish assignment from sink call
        next_tok = self._tokens[self._pos + 1] if self._pos + 1 < len(self._tokens) else None

        if next_tok and next_tok.type == ASSIGN:
            return self._parse_assignment()
        elif next_tok and next_tok.type == LPAREN:
            return self._parse_sink_call()
        else:
            raise SyntaxError(f"Line {tok.line}: unrecognised statement starting with {tok.value!r}")

    def _parse_assignment(self) -> Assignment:
        name_tok = self._consume(IDENT)
        self._consume(ASSIGN)
        value = self._parse_expr()
        self._expect_end_of_statement()
        return Assignment(line=name_tok.line, target=name_tok.value, value=value)

    def _parse_sink_call(self) -> SinkCall:
        name_tok = self._consume(IDENT)
        self._consume(LPAREN)
        args = self._parse_expr_list()
        self._consume(RPAREN)
        self._expect_end_of_statement()
        return SinkCall(line=name_tok.line, func=name_tok.value, args=args)

    def _expect_end_of_statement(self):
        tok = self._peek()
        if tok.type == NEWLINE:
            self._consume()
        elif tok.type == EOF:
            pass
        else:
            raise SyntaxError(f"Line {tok.line}: expected newline or EOF, got {tok.type} ({tok.value!r})")

    def _parse_expr_list(self) -> List[Expr]:
        exprs = []
        if self._peek().type == RPAREN:
            return exprs
        exprs.append(self._parse_expr())
        while self._peek().type == COMMA:
            self._consume(COMMA)
            exprs.append(self._parse_expr())
        return exprs

    def _parse_expr(self) -> Expr:
        left = self._parse_term()
        while self._peek().type == PLUS:
            self._consume(PLUS)
            right = self._parse_term()
            left = BinaryOp(line=left.line, left=left, op="+", right=right)
        return left

    def _parse_term(self) -> Expr:
        tok = self._peek()
        if tok.type == STRING:
            self._consume()
            return StringLiteral(line=tok.line, value=tok.value[1:-1])
        if tok.type == IDENT:
            # look ahead for call
            next_tok = self._tokens[self._pos + 1] if self._pos + 1 < len(self._tokens) else None
            if next_tok and next_tok.type == LPAREN:
                return self._parse_call()
            self._consume()
            return Variable(line=tok.line, name=tok.value)
        raise SyntaxError(f"Line {tok.line}: unexpected token {tok.type} ({tok.value!r}) in expression")

    def _parse_call(self) -> Call:
        name_tok = self._consume(IDENT)
        self._consume(LPAREN)
        args = self._parse_expr_list()
        self._consume(RPAREN)
        return Call(line=name_tok.line, func=name_tok.value, args=args)


def parse(source: str) -> Program:
    tokens = tokenize(source)
    return Parser(tokens).parse()
