use std::{fmt::Display, io::{self, BufWriter, Write}};

use crate::{RegexCompileError, RegexCompileErrorType, SourceLocation, Token, TokenType};

pub struct RegexAst {
    location: SourceLocation,
    has_hat: bool,
    has_dollar: bool,
    body: Body,
}

struct Body {
    location: SourceLocation,
    disjunctives: Vec<Expressions>,
}

struct Expressions {
    location: SourceLocation,
    expressions: Vec<Expression>,
}

struct Expression {
    location: SourceLocation,
    atom: Atom,
    expr_type: ExpressionType,
}

enum ExpressionType {
    Single,
    ZeroOrMore,
    OneOrMore,
    ZeroOrOne,
    AmountQuantifier(AmountQuantifier),
}

struct AmountQuantifier {
    location: SourceLocation,
    quantifier_type: AmountQuantifierType,
}

enum AmountQuantifierType {
    Min(u64),
    MinOrMore(u64),
    MinMax(u64, u64),
}

struct Atom {
    location: SourceLocation,
    atom_type: AtomType,
}

enum AtomType {
    Symbol(Symbol),
    Group(Body),
    Range { inverted: bool, ranges: Vec<Range> },
    All,
}

struct Range {
    location: SourceLocation,
    range_type: RangeType,
}

enum RangeType {
    Char(char),
    FromTo { from: char, to: char },
}

struct Symbol {
    location: SourceLocation,
    symbol_type: SymbolType,
}

enum SymbolType {
    EscapeGroup(char),
    Literal(char),
}

pub struct LL1Parser<I: Iterator<Item = Token>> {
    tokens: I,
    current_token: Token,
}

impl<I: Iterator<Item = Token>> LL1Parser<I> {
    pub fn new(mut tokens: I) -> Result<Self, RegexCompileError> {
        let first_token = tokens
            .next()
            .expect("Should never be None due to EOL token.");

        Ok(Self {
            tokens,
            current_token: first_token,
        })
    }

    fn accept(&mut self, expected: TokenType) -> Result<char, RegexCompileError> {
        let c = self.current_token.char;
        if self.current_token.ttype == expected {
            self.current_token = self
                .tokens
                .next()
                .expect("Should never be None due to EOL token.");
            Ok(c)
        } else if self.current_token.ttype == TokenType::EOL {
            return Err(RegexCompileError::new(
                self.current_token.location,
                RegexCompileErrorType::UnexpectedEOL,
            ));
        } else {
            Err(RegexCompileError::new(
                self.current_token.location,
                RegexCompileErrorType::Syntax {
                    actual: self.current_token.ttype,
                    expected: vec![expected],
                },
            ))
        }
    }

    fn accept_it(&mut self) -> Result<char, RegexCompileError> {
        if self.current_token.ttype == TokenType::EOL {
            return Err(RegexCompileError::new(
                self.current_token.location,
                RegexCompileErrorType::UnexpectedEOL,
            ));
        }
        let c = self.current_token.char;
        self.current_token = self
            .tokens
            .next()
            .expect("Should never be None due to EOL token.");
        Ok(c)
    }

    // regex ::= '^'? body '$'?
    // TODO: should it be body? instead of body aka is an empty regex a valid regex
    pub fn parse(&mut self) -> Result<RegexAst, RegexCompileError> {
        let location = self.current_token.location;

        let has_hat = if matches!(self.current_token.ttype, TokenType::Hat) {
            self.accept_it()?;
            true
        } else {
            false
        };

        let body = self.parse_body()?;

        let has_dollar = if matches!(self.current_token.ttype, TokenType::Dollar) {
            self.accept_it()?;
            true
        } else {
            false
        };

        Ok(RegexAst {
            location,
            has_hat,
            body,
            has_dollar,
        })
    }

    //body ::= expressions ( '|' expressions )*
    fn parse_body(&mut self) -> Result<Body, RegexCompileError> {
        let location = self.current_token.location;

        let mut disjunctives = Vec::new();

        disjunctives.push(self.parse_expressions()?);

        while self.current_token.ttype == TokenType::Bar {
            self.accept_it()?;
            disjunctives.push(self.parse_expressions()?);
        }

        Ok(Body {
            location,
            disjunctives,
        })
    }

    // expressions ::= expr+
    fn parse_expressions(&mut self) -> Result<Expressions, RegexCompileError> {
        let location = self.current_token.location;
        let mut expressions = Vec::new();

        // The same tokens needed for matching an atom
        while matches!(
            self.current_token.ttype,
            TokenType::Literal
                | TokenType::Dot
                | TokenType::OpeningParentheses
                | TokenType::OpeningBracket
                | TokenType::Escape
        ) {
            expressions.push(self.parse_expr()?);
        }

        Ok(Expressions {
            location,
            expressions,
        })
    }

    // expr ::= atom ( '*' | '+' | '?' | '{' amountExpr '}' )?
    fn parse_expr(&mut self) -> Result<Expression, RegexCompileError> {
        let location = self.current_token.location;
        let atom = self.parse_atom()?;

        let expr_type = match self.current_token.ttype {
            TokenType::Star => {
                self.accept_it()?;
                ExpressionType::ZeroOrMore
            }
            TokenType::Plus => {
                self.accept_it()?;
                ExpressionType::OneOrMore
            }
            TokenType::QuestionMark => {
                self.accept_it()?;
                ExpressionType::ZeroOrOne
            }
            TokenType::OpeningAmountBracket => {
                self.accept_it()?;

                let amount_quantifier = self.parse_amount_expression()?;

                self.accept(TokenType::ClosingAmountBracket)?;

                ExpressionType::AmountQuantifier(amount_quantifier)
            }
            _ => ExpressionType::Single,
        };

        Ok(Expression {
            location,
            atom,
            expr_type,
        })
    }

    // atom ::= symbol | '.' | '(' body ')' | '[' rangeExpr ']'
    fn parse_atom(&mut self) -> Result<Atom, RegexCompileError> {
        let location = self.current_token.location;
        Ok(Atom {
            location,
            atom_type: match self.current_token.ttype {
                TokenType::Escape | TokenType::Literal => AtomType::Symbol(self.parse_symbol()?),
                TokenType::Dot => {
                    self.accept_it()?;

                    AtomType::All
                }
                TokenType::OpeningBracket => {
                    self.accept_it()?;

                    let (inverted, ranges) = self.parse_range()?;

                    self.accept(TokenType::ClosingBracket)?;

                    AtomType::Range { inverted, ranges }
                }
                TokenType::OpeningParentheses => {
                    self.accept_it()?;

                    let body = self.parse_body()?;

                    self.accept(TokenType::ClosingParantheses)?;

                    AtomType::Group(body)
                }
                token_type => {
                    return Err(RegexCompileError::new(
                        location,
                        RegexCompileErrorType::Syntax {
                            actual: token_type,
                            expected: vec![
                                TokenType::Escape,
                                TokenType::Literal,
                                TokenType::Dot,
                                TokenType::OpeningParentheses,
                                TokenType::OpeningBracket,
                            ],
                        },
                    ))
                }
            },
        })
    }

    // amountExpr ::= number (',' number? )?
    fn parse_amount_expression(&mut self) -> Result<AmountQuantifier, RegexCompileError> {
        let location = self.current_token.location;
        let min = self.parse_num()?;

        let quantifier_type = if self.current_token.ttype == TokenType::Comma {
            self.accept_it()?;

            if self.current_token.ttype == TokenType::ClosingAmountBracket {
                AmountQuantifierType::MinOrMore(min)
            } else {
                AmountQuantifierType::MinMax(min, self.parse_num()?)
            }
        } else {
            AmountQuantifierType::Min(min)
        };

        Ok(AmountQuantifier {
            location,
            quantifier_type,
        })
    }

    // number ::= literal+
    fn parse_num(&mut self) -> Result<u64, RegexCompileError> {
        let location = self.current_token.location;
        let mut number_string = String::new();
        number_string.push(self.accept(TokenType::Literal)?);

        while self.current_token.ttype == TokenType::Literal {
            let c = self.accept_it()?;
            number_string.push(c);
        }

        Ok(u64::from_str_radix(&number_string, 10).map_err(|err| {
            RegexCompileError::new(location, RegexCompileErrorType::IntegerParsing(err))
        })?)
    }

    // rangeExpr ::= '^'? ( symbol ('-' symbol)? )+
    fn parse_range(&mut self) -> Result<(bool, Vec<Range>), RegexCompileError> {
        let inverted = if self.current_token.ttype == TokenType::Hat {
            self.accept_it()?;
            true
        } else {
            false
        };

        let mut ranges = Vec::new();

        ranges.push(self.parse_inner_range()?);

        while self.current_token.ttype != TokenType::ClosingBracket {
            ranges.push(self.parse_inner_range()?);
        }

        Ok((inverted, ranges))
    }

    // range_literal ('-' literal)?
    fn parse_inner_range(&mut self) -> Result<Range, RegexCompileError> {
        let location = self.current_token.location;
        let start = self.parse_range_literal()?;

        let range_type = if self.current_token.ttype == TokenType::Minus {
            self.accept_it()?;
            let end = self.accept(TokenType::Literal)?;

            RangeType::FromTo {
                from: start,
                to: end,
            }
        } else {
            RangeType::Char(start)
        };

        return Ok(Range {
            location,
            range_type,
        });
    }

    fn parse_range_literal(&mut self) -> Result<char, RegexCompileError> {
        let location = self.current_token.location;
        if self.current_token.ttype == TokenType::Literal {
            let c = self.accept_it()?;
            Ok(c)
        } else if self.current_token.ttype == TokenType::Escape {
            self.accept_it()?;
            if self.current_token.ttype == TokenType::Literal {
                return Err(RegexCompileError::new(
                    location,
                    RegexCompileErrorType::EscapeGroupInRange {
                        group: self.accept_it()?,
                    },
                ));
            }

            Ok(self.accept_it()?)
        } else {
            Ok(self.accept_it()?)
        }
    }

    // literal | '\'.
    fn parse_symbol(&mut self) -> Result<Symbol, RegexCompileError> {
        let location = self.current_token.location;
        if self.current_token.ttype == TokenType::Literal {
            let c = self.accept_it()?;
            return Ok(Symbol {
                location,
                symbol_type: SymbolType::Literal(c),
            });
        }

        self.accept(TokenType::Escape)?;

        return Ok(Symbol {
            location,
            symbol_type: match self.current_token.ttype {
                TokenType::Literal => SymbolType::EscapeGroup(self.accept_it()?),
                _ => SymbolType::Literal(self.accept_it()?),
            },
        });
    }
}

pub struct PrettyPrinter<T: Write> {
    buf: BufWriter<T>,
}

impl<T: Write> PrettyPrinter<T> {
    pub fn new(buf: BufWriter<T>) -> Self {
        PrettyPrinter { buf }
    }

    pub fn pretty_print_ast(&mut self, ast: &RegexAst, original: &str) -> io::Result<()> {
        writeln!(&mut self.buf, "Abstract Syntax Tree for {}", original)?;
        writeln!(&mut self.buf, "Starts with Hat: {}", ast.has_hat)?;
        writeln!(&mut self.buf, "Ends with Dollar: {}", ast.has_dollar)?;
        self.pp_body(&ast.body, 0);
        self.buf.flush()?;

        Ok(())
    }

    fn pp_body(&mut self, body: &Body, indentation_level: usize) -> io::Result<()> {
        write!(&mut self.buf, "{}", "| ".repeat(indentation_level))?;
        writeln!(&mut self.buf, "Body:")?;
        for disjunctive in &body.disjunctives {
            self.pp_disjunctive(disjunctive, indentation_level + 1);
        }

        Ok(())
    }

    fn pp_disjunctive(&mut self, disjunctive: &Expressions, indentation_level: usize) -> io::Result<()> {
        write!(&mut self.buf, "{}", "| ".repeat(indentation_level))?;
        writeln!(&mut self.buf, "Expressions:")?;
        for expression in &disjunctive.expressions {
            self.pp_expression(expression, indentation_level + 1)?;
        }

        Ok(())
    }

    fn pp_expression(&mut self, expr: &Expression, indentation_level: usize) -> io::Result<()> {
        write!(&mut self.buf, "{}", "| ".repeat(indentation_level))?;
        match &expr.expr_type {
            ExpressionType::Single => {
                writeln!(&mut self.buf, "Single:")?;
            }
            ExpressionType::ZeroOrMore => {
                writeln!(&mut self.buf, "ZeroOrMore (*):")?;
            }
            ExpressionType::OneOrMore => {
                writeln!(&mut self.buf, "OneOrMore (+):")?;
            }
            ExpressionType::ZeroOrOne => {
                writeln!(&mut self.buf, "ZeroOrOne (?):")?;
            }
            ExpressionType::AmountQuantifier(amount_quantifier) => {
                match amount_quantifier.quantifier_type {
                    AmountQuantifierType::Min(min) => {
                        writeln!(&mut self.buf, "AmountQuantifier ({}):", min)?;
                    }
                    AmountQuantifierType::MinOrMore(min) => {
                        writeln!(&mut self.buf, "AmountQuantifier ({},):", min)?;
                    }
                    AmountQuantifierType::MinMax(min, max) => {
                        writeln!(&mut self.buf, "AmountQuantifier ({},{}):", min, max)?;
                    }
                }
            }
        }
        self.pp_atom(&expr.atom, indentation_level + 1)?;

        Ok(())
    }

    fn pp_atom(&mut self, atom: &Atom, indentation_level: usize) -> io::Result<()> {
        write!(&mut self.buf, "{}", "| ".repeat(indentation_level))?;
        match &atom.atom_type {
            AtomType::Symbol(sym) => {
                writeln!(&mut self.buf, "Symbol Atom:")?;
                self.pp_symbol(&sym, indentation_level + 1)?;
            }
            AtomType::Group(body) => {
                writeln!(&mut self.buf, "Group Atom:")?;
                self.pp_body(&body, indentation_level + 1)?;
            }
            AtomType::Range { inverted, ranges } => {
                writeln!(&mut self.buf, "Range Atom (inverted: {}):", inverted)?;
                for range in ranges {
                    self.pp_range(&range, indentation_level + 1)?;
                }
            }
            AtomType::All => {
                writeln!(&mut self.buf, "All Atom:")?;
            }
        }
        Ok(())
    }

    fn pp_symbol(&mut self, symbol: &Symbol, indentation_level: usize) -> io::Result<()> {
        write!(&mut self.buf, "{}", "| ".repeat(indentation_level))?;
        match &symbol.symbol_type {
            SymbolType::EscapeGroup(x) => {
                writeln!(&mut self.buf, "Escape Group '{}'", x)?;
            }
            SymbolType::Literal(x) => {
                writeln!(&mut self.buf, "Literal '{}'", x)?;
            }
        }
        Ok(())
    }

    fn pp_range(&mut self, range: &Range, indentation_level: usize) -> io::Result<()> {
        write!(&mut self.buf, "{}", "| ".repeat(indentation_level))?;
        match &range.range_type {
            RangeType::Char(sym) => {
                writeln!(&mut self.buf, "Symbol Range ({})", sym)?;
            }
            RangeType::FromTo { from, to } => {
                writeln!(&mut self.buf, "FromTo Range ({} - {})", from, to)?;
            }
        }
        Ok(())
    }
}
