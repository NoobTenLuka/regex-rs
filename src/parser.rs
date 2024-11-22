use crate::{RegexCompileError, Token};

struct RegexNode {
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
    AmountQuantifier {
        min: u64,
        max: Option<u64>
    },
}

enum Atom {
    Symbol(char),
    Group(Body),
    Range {
        inverted: bool,
        ranges: Vec<Range>
    }
}

enum Range {
    Symbol(char),
    FromTo {
        from: char,
        to: char
    }
}

struct LL1Parser<I: Iterator<Item = Token>> {
    tokens: I,
    current_token: Token
}

impl<I: Iterator<Item = Token>> LL1Parser<I> {
    fn new(mut tokens: I) -> Result<Self, RegexCompileError> {
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
    fn parse(&mut self) -> Result<RegexNode, RegexCompileError> {
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

        Ok(RegexNode {
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

                let (min, max) = self.parse_amount_expression()?;

                self.accept(Token::ClosingAmountBracket)?;

                ExpressionType::AmountQuantifier { min, max }
            },
            _ => ExpressionType::Single
        };

        Ok(Expression { atom, expr_type })
    }

    // atom ::= symbol | '(' body ')' | '[' rangeExpr ']'
    fn parse_atom(&mut self) -> Result<Atom, RegexCompileError> {
        Ok(match self.current_token {
            Token::Escape => todo!(), //TODO: Deal with escapes properly
            Token::Literal(x) => {
                self.accept_it()?;
                Atom::Symbol(x)
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
    fn parse_amount_expression(&mut self) -> Result<(u64, Option<u64>), RegexCompileError> {
        let min = self.parse_num()?;

        let max = if self.current_token == Token::Comma {
            self.accept_it()?;

            Some(self.parse_num()?)
        } else { None };

        Ok((min, max))
    }

    // number ::= literal+
    fn parse_num(&mut self) -> Result<u64, RegexCompileError> {
        let mut num = 0;
        while let Token::Literal(c) = self.current_token {
            self.accept_it()?;
            num = num * 10
                + c.to_digit(10)
                    .ok_or(RegexCompileError::UnexpectedSymbolError(c))? as u64;
            //TODO: check if u64 exceeded
        };

        Ok(num)
    }

    // rangeExpr ::= '^'? ( symbol ('-' symbol)? )+
    fn parse_range(&mut self) -> Result<(bool, Vec<Range>), RegexCompileError> {
        let inverted = if self.current_token == Token::Hat {
            self.accept_it()?;
            true
        } else { false };

        let ranges = Vec::new();

        

        Ok((inverted, ranges))
    }
}
