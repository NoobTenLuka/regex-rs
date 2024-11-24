use std::io::{self, BufWriter, Stdout, Write};

use crate::{RegexCompileError, Token};

struct RegexAst {
    has_hat: bool,
    has_dollar: bool,
    body: Body
}

struct Body {
    disjunctives: Vec<Expressions>
}

struct Expressions {
    expressions: Vec<Expression>
}

struct Expression {
    atom: Atom,
    expr_type: ExpressionType,
}

enum ExpressionType {
    Single,
    ZeroOrMore,
    OneOrMore,
    ZeroOrOne,
    AmountQuantifier(AmountQuantifier)
}

enum AmountQuantifier {
    Min(u64),
    MinOrMore(u64),
    MinMax(u64, u64)
}

enum Atom {
    Symbol(Symbol),
    Group(Body),
    Range {
        inverted: bool,
        ranges: Vec<Range>
    }
}

enum Range {
    Symbol(Symbol),
    FromTo {
        from: char,
        to: char
    }
}

enum Symbol {
    EscapeGroup(char),
    Literal(char)
}

pub struct LL1Parser<I: Iterator<Item = Token>> {
    tokens: I,
    current_token: Token
}

impl<I: Iterator<Item = Token>> LL1Parser<I> {
    pub fn new(mut tokens: I) -> Result<Self, RegexCompileError> {
        let first_token = tokens.next().ok_or(RegexCompileError::EmptyError)?;

        Ok(Self {
            tokens,
            current_token: first_token
        })
    }

    fn accept(&mut self, expected: Token) -> Result<(), RegexCompileError> {
        if self.current_token == expected {
            self.current_token = self.tokens.next().ok_or(RegexCompileError::EmptyError)?;
            Ok(())
        } else {
            Err(RegexCompileError::MissingSymbolError)
        }
    }

    fn accept_lit(&mut self) -> Result<char, RegexCompileError> {
        if let Token::Literal(literal) = self.current_token {
            self.current_token = self.tokens.next().ok_or(RegexCompileError::EmptyError)?;
            Ok(literal)
        } else {
            Err(RegexCompileError::MissingSymbolError)
        }
    }

    fn accept_it(&mut self) -> Result<(), RegexCompileError> {
        self.current_token = self.tokens.next().ok_or(RegexCompileError::EmptyError)?;

        Ok(())
    }

    // regex ::= '^'? body '$'?
    pub fn parse(&mut self) -> Result<RegexAst, RegexCompileError> {
        let has_hat = if matches!(self.current_token, Token::Hat) {
            self.accept_it()?;
            true
        } else {
            false
        };

        let body = self.parse_body()?;

        let has_dollar = if matches!(self.current_token, Token::Dollar) {
            self.accept_it();
            true
        } else {
            false
        };

        Ok(RegexAst {
            has_hat, body, has_dollar 
        })
    }

    //body ::= expressions ( '|' expressions )*
    fn parse_body(&mut self) -> Result<Body, RegexCompileError> {
        let mut disjunctives = Vec::new();

        disjunctives.push(self.parse_expressions()?);

        while self.current_token == Token::Bar {
            self.accept_it();
            disjunctives.push(self.parse_expressions()?);
        }

        Ok(Body {
            disjunctives,
        })
    }

    // expressions ::= expr+
    fn parse_expressions(&mut self) -> Result<Expressions, RegexCompileError> {
        let mut expressions = Vec::new();

        // The same tokens needed for matching an atom
        while matches!(self.current_token, Token::Literal(_) | Token::OpeningParentheses | Token::OpeningBracket | Token::Escape) {
            expressions.push(self.parse_expr()?);
        }

        Ok(Expressions {
            expressions
        })
    }

    // expr ::= atom ( '*' | '+' | '?' | '{' amountExpr '}' )?
    fn parse_expr(&mut self) -> Result<Expression, RegexCompileError> {
        let atom = self.parse_atom()?;

        let expr_type = match self.current_token {
            Token::Star => {
                self.accept_it()?;
                ExpressionType::ZeroOrMore
            },
            Token::Plus => {
                self.accept_it()?;
                ExpressionType::OneOrMore
            },
            Token::QuestionMark => {
                self.accept_it()?;
                ExpressionType::ZeroOrOne
            },
            Token::OpeningAmountBracket => {
                self.accept_it()?;

                let amount_quantifier = self.parse_amount_expression()?;

                self.accept(Token::ClosingAmountBracket)?;

                ExpressionType::AmountQuantifier(amount_quantifier)
            },
            _ => ExpressionType::Single
        };

        Ok(Expression { atom, expr_type })
    }

    // atom ::= symbol | '(' body ')' | '[' rangeExpr ']'
    fn parse_atom(&mut self) -> Result<Atom, RegexCompileError> {
        Ok(match self.current_token {
            Token::Escape | Token::Literal(_) => {
                Atom::Symbol(self.parse_symbol()?)
            }
            Token::OpeningBracket => {
                self.accept_it()?;

                let (inverted, ranges) = self.parse_range()?;

                self.accept(Token::ClosingBracket)?;

                Atom::Range { inverted, ranges }
            }
            Token::OpeningParentheses => {
                self.accept_it()?;

                let body = self.parse_body()?;

                self.accept(Token::ClosingParantheses)?;

                Atom::Group(body)
            }
            _ => return Err(RegexCompileError::UnexpectedSymbolError('x')) //TODO: Improve Errors
        })
    }

    // amountExpr ::= number (',' number? )?
    fn parse_amount_expression(&mut self) -> Result<AmountQuantifier, RegexCompileError> {
        let min = self.parse_num()?;

        if self.current_token == Token::Comma {
            self.accept_it()?;

            if self.current_token == Token::ClosingAmountBracket {
                return Ok(AmountQuantifier::MinOrMore(min))
            }

            return Ok(AmountQuantifier::MinMax(min, self.parse_num()?))
        }

        Ok(AmountQuantifier::Min(min))
    }

    // number ::= literal+
    fn parse_num(&mut self) -> Result<u64, RegexCompileError> {
        let mut number_string = String::new();
        number_string.push(self.accept_lit()?);

        while let Token::Literal(c) = self.current_token {
            self.accept_it()?;
            number_string.push(c);
        };

        Ok(u64::from_str_radix(&number_string, 10).map_err(|_| RegexCompileError::EmptyError)?) // TODO: Replace empty error with better errors depending of too big, or invalid chars
    }

    // rangeExpr ::= '^'? ( symbol ('-' symbol)? )+
    fn parse_range(&mut self) -> Result<(bool, Vec<Range>), RegexCompileError> {
        let inverted = if self.current_token == Token::Hat {
            self.accept_it()?;
            true
        } else { false };

        let mut ranges = Vec::new();

        ranges.push(self.parse_inner_range()?);

        while self.current_token != Token::ClosingBracket {
            ranges.push(self.parse_inner_range()?);
        }

        Ok((inverted, ranges))
    }

    // symbol ('-' literal)?
    fn parse_inner_range(&mut self) -> Result<Range, RegexCompileError> {
        let start = self.parse_symbol()?;

        if self.current_token == Token::Minus {
            let start = if let Symbol::Literal(x) = start {
                x
            } else {
                return Err(RegexCompileError::EmptyError) // TODO: make an error like unallowed
                                                          // escape group error
            };

            self.accept_it();
            let end = self.accept_lit()?;

            return Ok(Range::FromTo { from: start, to: end })
        } 

        return Ok(Range::Symbol(start))
    }

    // literal | '\'.
    fn parse_symbol(&mut self) -> Result<Symbol, RegexCompileError> {
        if let Token::Literal(x) = self.current_token {
            self.accept_it()?;
            return Ok(Symbol::Literal(x));
        }

        self.accept(Token::Escape)?;

        return Ok(Symbol::Literal(match self.current_token {
            Token::Star => '*',
            Token::Plus => '+',
            Token::Dot => '.',
            Token::OpeningBracket => '[',
            Token::ClosingBracket => ']',
            Token::OpeningAmountBracket => '{',
            Token::ClosingAmountBracket => '}',
            Token::OpeningParentheses => '(',
            Token::ClosingParantheses => ')',
            Token::Escape => '\\',
            Token::QuestionMark => '?',
            Token::Dollar => '$',
            Token::Hat => '^',
            Token::Minus => '-',
            Token::Bar => '|',
            Token::Comma => ',',
            Token::EOL => {
                return Err(RegexCompileError::EmptyError)
            },
            Token::Literal(x) => {
                return Ok(Symbol::EscapeGroup(x))
            }
        }))
    }
}

struct PrettyPrinter<T: Write> {
    buf: BufWriter<T>
}

impl<T: Write> PrettyPrinter<T> {
    pub fn pretty_print_ast(&mut self, ast: RegexAst, original: &str) {
        writeln!(&mut self.buf, "Abstract Syntax Tree for {}", original);
        writeln!(&mut self.buf, "Starts with Hat: {}", ast.has_hat);
        writeln!(&mut self.buf, "Ends with Dollar: {}", ast.has_dollar);
        self.pp_body(ast.body, 0);
    }

    fn pp_body(&mut self, body: Body, indentation_level: usize) {
        write!(&mut self.buf, "{}", "| ".repeat(indentation_level));
        writeln!(&mut self.buf, "Body:");
        for disjunctive in body.disjunctives {
            self.pp_disjunctive(disjunctive, indentation_level + 1);
        }
    }

    fn pp_disjunctive(&mut self, disjunctive: Expressions, indentation_level: usize) {
        write!(&mut self.buf, "{}", "| ".repeat(indentation_level));
        writeln!(&mut self.buf, "Expressions:");
        for expression in disjunctive.expressions {
            self.pp_expression(expression, indentation_level + 1);
        }
    }

    fn pp_expression(&mut self, expr: Expression, indentation_level: usize) {
        write!(&mut self.buf, "{}", "| ".repeat(indentation_level));
        match expr.expr_type {
            ExpressionType::Single => {
                writeln!(&mut self.buf, "Single:");
            },
            ExpressionType::ZeroOrMore => {
                writeln!(&mut self.buf, "ZeroOrMore (*):");
            },
            ExpressionType::OneOrMore => {
                writeln!(&mut self.buf, "OneOrMore (+):");
            },
            ExpressionType::ZeroOrOne => {
                writeln!(&mut self.buf, "ZeroOrOne (?):");
            },
            ExpressionType::AmountQuantifier(amount_quantifier) => {
                match amount_quantifier {
                    AmountQuantifier::Min(min) => {
                        writeln!(&mut self.buf, "AmountQuantifier ({}):", min);
                    },
                    AmountQuantifier::MinOrMore(min) => {
                        writeln!(&mut self.buf, "AmountQuantifier ({},):", min);
                    },
                    AmountQuantifier::MinMax(min, max) => {
                        writeln!(&mut self.buf, "AmountQuantifier ({},{}):", min, max);
                    },
                }
            },
        }
        self.pp_atom(expr.atom, indentation_level + 1);
    }

    fn pp_atom(&mut self, atom: Atom, indentation_level: usize) {
        
    }
}
