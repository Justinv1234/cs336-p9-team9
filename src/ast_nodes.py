from dataclasses import dataclass, field
from typing import List


@dataclass
class Expr:
    line: int


@dataclass
class Variable(Expr):
    name: str


@dataclass
class StringLiteral(Expr):
    value: str


@dataclass
class Call(Expr):
    func: str
    args: List[Expr] = field(default_factory=list)


@dataclass
class BinaryOp(Expr):
    left: Expr
    op: str
    right: Expr


@dataclass
class Statement:
    line: int


@dataclass
class Assignment(Statement):
    target: str
    value: Expr


@dataclass
class SinkCall(Statement):
    func: str
    args: List[Expr] = field(default_factory=list)


@dataclass
class Program:
    statements: List[Statement] = field(default_factory=list)
