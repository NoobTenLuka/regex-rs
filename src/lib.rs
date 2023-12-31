use std::{collections::HashMap, fmt::Display};

#[derive(PartialEq, Eq)]
enum Token {
    Star,
    Plus,
    Dot,
    OpeningBracket,
    ClosingBracket,
    OpeningAmountBracket,
    ClosingAmountBracket,
    Escape,
    QuestionMark,
    Dollar,
    Hat,
    Minus,
    Comma,
    Literal(char),
}

#[derive(PartialEq, Eq, Debug)]
enum AstNode {
    Root(Vec<AstNode>),
    Star(Box<AstNode>),
    Plus(Box<AstNode>),
    QuestionMark(Box<AstNode>),
    Amount(Box<AstNode>, usize),
    MoreThan(Box<AstNode>, usize),
    Between(Box<AstNode>, usize, usize),
    Dot,
    Bracket(Vec<AstNode>),
    Dollar,
    Hat,
    NotIn(Box<AstNode>),
    Literal(char),
}

#[derive(Debug, PartialEq, Eq)]
struct DfaNode {
    accepting: bool,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
enum TransitionFilter {
    None,
    Char(char),
    All,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum TransitionTarget {
    State(usize),
    Fail,
}

type Transition = (usize, TransitionFilter, TransitionTarget);

#[derive(Debug, PartialEq, Eq)]
pub enum RegexCompileError {
    MissingSymbolError,
    MissingBracketError(char),
    UnexpectedSymbolError(char),
    EmptyError,
    SymbolAfterDollarError,
    DanglingModifierError,
    MinGreaterMaxError,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Regex {
    dfa_nodes: Vec<DfaNode>,
    dfa_transitions: HashMap<(usize, TransitionFilter), TransitionTarget>,
    starts_with_hat: bool,
    ends_with_dollar: bool,
}

impl Display for Regex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Starts with hat: {:?}", self.starts_with_hat)?;
        writeln!(f, "Ends with dollar: {:?}", self.ends_with_dollar)?;

        for (i, node) in self.dfa_nodes.iter().enumerate() {
            let mut to_self = self
                .dfa_transitions
                .iter()
                .filter(|((start, _), end)| *start == i && **end == TransitionTarget::State(i));

            let to_next = self
                .dfa_transitions
                .iter()
                .filter(|((start, _), end)| *start == i && **end == TransitionTarget::State(i + 1));

            let to_second_next = self
                .dfa_transitions
                .iter()
                .filter(|((start, _), end)| *start == i && **end == TransitionTarget::State(i + 2));

            let to_fail = self
                .dfa_transitions
                .iter()
                .filter(|((start, _), end)| *start == i && **end == TransitionTarget::Fail);

            if node.accepting {
                write!(f, "A")?;
            }

            write!(f, "({i:0>3})")?;
            if let Some(x) = to_self.next() {
                write!(f, " ⮌ {:?}", x.0 .1)?;
            }
            for x in to_self {
                write!(f, " ,{:?}", x.0 .1)?;
            }
            writeln!(f)?;

            for x in to_fail {
                writeln!(f, " ← {:?}", x.0 .1)?;
            }

            for x in to_next {
                writeln!(f, "  ↓ {:?}", x.0 .1)?;
            }

            for x in to_second_next {
                writeln!(f, "  2  ↓ {:?}", x.0 .1)?;
            }
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct RegexOptions {
    pretty_print_ast: bool,
}

impl Regex {
    pub fn new(regex: &str) -> Result<Self, RegexCompileError> {
        Self::new_with_options(regex, RegexOptions::default())
    }

    pub fn new_with_options(regex: &str, options: RegexOptions) -> Result<Self, RegexCompileError> {
        let mut token_stream = Self::lex(regex);

        let ast = Self::parse(&mut token_stream)?;

        if options.pretty_print_ast {
            Self::pprint_ast(&ast, 0);
        }

        let (dfa_nodes, dfa_transitions, starts_with_hat, ends_with_dollar) = Self::codegen(ast);

        Ok(Regex {
            dfa_nodes,
            dfa_transitions: HashMap::from_iter(
                dfa_transitions.iter().map(|(s, t, e)| ((*s, *t), *e)),
            ),
            starts_with_hat,
            ends_with_dollar,
        })
    }

    // Input String -> Token Stream
    fn lex(source: &str) -> impl Iterator<Item = Token> + '_ {
        source.chars().map(|c| match c {
            '*' => Token::Star,
            '+' => Token::Plus,
            '.' => Token::Dot,
            '[' => Token::OpeningBracket,
            ']' => Token::ClosingBracket,
            '{' => Token::OpeningAmountBracket,
            '}' => Token::ClosingAmountBracket,
            '?' => Token::QuestionMark,
            '\\' => Token::Escape,
            '$' => Token::Dollar,
            '^' => Token::Hat,
            '-' => Token::Minus,
            ',' => Token::Comma,
            x => Token::Literal(x),
        })
    }

    // Token Stream -> Abstract Syntax Tree
    fn parse(tokens: &mut impl Iterator<Item = Token>) -> Result<AstNode, RegexCompileError> {
        let mut root_vec = Vec::new();
        let mut has_dollar = false;

        let first_token = tokens.next().ok_or(RegexCompileError::EmptyError)?;
        if first_token != Token::Hat {
            let new_node = Self::parse_rule(first_token, tokens, &mut root_vec, &mut has_dollar)?;

            root_vec.push(new_node);
        } else {
            root_vec.push(AstNode::Hat);
        }

        while let Some(token) = tokens.next() {
            let new_node = Self::parse_rule(token, tokens, &mut root_vec, &mut has_dollar)?;

            root_vec.push(new_node);
        }

        Ok(AstNode::Root(root_vec))
    }

    fn parse_rule(
        token: Token,
        rest_tokens: &mut impl Iterator<Item = Token>,
        root_vec: &mut Vec<AstNode>,
        has_dollar: &mut bool,
    ) -> Result<AstNode, RegexCompileError> {
        if *has_dollar {
            return Err(RegexCompileError::SymbolAfterDollarError);
        }

        match token {
            Token::Star | Token::QuestionMark | Token::Plus | Token::OpeningAmountBracket => {
                Self::parse_modifier(token, rest_tokens, root_vec)
            }
            Token::Dot => Ok(AstNode::Dot),
            Token::OpeningBracket => Self::parse_bracket(rest_tokens),
            Token::Escape => Ok(Self::parse_escape(
                rest_tokens
                    .next()
                    .ok_or(RegexCompileError::MissingSymbolError)?,
            )),
            Token::Literal(c) => Ok(AstNode::Literal(c)),
            Token::ClosingBracket => Err(RegexCompileError::UnexpectedSymbolError(']')),
            Token::ClosingAmountBracket => Err(RegexCompileError::UnexpectedSymbolError('}')),
            Token::Hat => Err(RegexCompileError::UnexpectedSymbolError('^')),
            Token::Minus => Err(RegexCompileError::UnexpectedSymbolError('-')),
            Token::Comma => Err(RegexCompileError::UnexpectedSymbolError(',')),
            Token::Dollar => {
                *has_dollar = true;
                Ok(AstNode::Dollar)
            }
        }
    }

    fn parse_modifier(
        token: Token,
        rest_tokens: &mut impl Iterator<Item = Token>,
        root_vec: &mut Vec<AstNode>,
    ) -> Result<AstNode, RegexCompileError> {
        let previous_node = root_vec
            .pop()
            .ok_or(RegexCompileError::DanglingModifierError)?;

        if matches!(
            previous_node,
            AstNode::Hat
                | AstNode::Star(_)
                | AstNode::Dollar
                | AstNode::Plus(_)
                | AstNode::QuestionMark(_)
                | AstNode::Amount(_, _)
                | AstNode::MoreThan(_, _)
                | AstNode::Between(_, _, _)
        ) {
            return Err(RegexCompileError::DanglingModifierError);
        }

        let boxed_prev_node = Box::new(previous_node);

        Ok(match token {
            Token::Star => AstNode::Star(boxed_prev_node),
            Token::Plus => AstNode::Plus(boxed_prev_node),
            Token::QuestionMark => AstNode::QuestionMark(boxed_prev_node),
            Token::OpeningAmountBracket => {
                Self::parse_amount_bracket(rest_tokens, boxed_prev_node)?
            }
            _ => unreachable!(),
        })
    }

    fn parse_bracket(
        tokens: &mut impl Iterator<Item = Token>,
    ) -> Result<AstNode, RegexCompileError> {
        let mut bracket_chars = Vec::new();
        let mut starts_with_hat = false;
        while let Some(token) = tokens.next() {
            match token {
                Token::Hat => {
                    if bracket_chars.is_empty() {
                        starts_with_hat = true;
                    } else {
                        let new_node = Self::parse_bracket_char(Token::Hat);
                        bracket_chars.push(new_node);
                    }
                }
                Token::Minus => {
                    let prev_node = bracket_chars
                        .pop()
                        .ok_or(RegexCompileError::UnexpectedSymbolError('-'))?;
                    let next_token = tokens.next().ok_or(RegexCompileError::MissingSymbolError)?;
                    if next_token == Token::Minus {
                        return Err(RegexCompileError::UnexpectedSymbolError('-'));
                    }
                    let next_node = Self::parse_bracket_char(next_token);

                    if let AstNode::Literal(from) = prev_node {
                        if let AstNode::Literal(to) = next_node {
                            for char in from..=to {
                                bracket_chars.push(AstNode::Literal(char));
                            }
                        }
                    }
                }
                Token::ClosingBracket => {
                    return if starts_with_hat {
                        Ok(AstNode::NotIn(Box::new(AstNode::Bracket(bracket_chars))))
                    } else {
                        Ok(AstNode::Bracket(bracket_chars))
                    }
                }
                Token::Escape => {
                    let new_node = Self::parse_escape(
                        tokens.next().ok_or(RegexCompileError::MissingSymbolError)?,
                    );
                    bracket_chars.push(new_node);
                }
                x => {
                    let new_node = Self::parse_bracket_char(x);
                    bracket_chars.push(new_node);
                }
            };
        }
        Err(RegexCompileError::MissingBracketError(']'))
    }

    fn parse_amount_bracket(
        tokens: &mut impl Iterator<Item = Token>,
        boxed_prev_node: Box<AstNode>,
    ) -> Result<AstNode, RegexCompileError> {
        let mut next_token = tokens.next().ok_or(RegexCompileError::MissingSymbolError)?;

        let mut min_num = 0usize;
        while let Token::Literal(c) = next_token {
            min_num = min_num * 10
                + c.to_digit(10)
                    .ok_or(RegexCompileError::UnexpectedSymbolError(c))? as usize;

            next_token = tokens
                .next()
                .ok_or(RegexCompileError::MissingBracketError('}'))?;
        }

        if next_token == Token::ClosingAmountBracket {
            return Ok(AstNode::Amount(boxed_prev_node, min_num));
        }

        if next_token != Token::Comma {
            return Err(RegexCompileError::MissingSymbolError);
        }

        next_token = tokens
            .next()
            .ok_or(RegexCompileError::MissingBracketError('}'))?;

        if next_token == Token::ClosingAmountBracket {
            return Ok(AstNode::MoreThan(boxed_prev_node, min_num));
        }

        let mut max_num = 0usize;
        while let Token::Literal(c) = next_token {
            max_num = max_num * 10
                + c.to_digit(10)
                    .ok_or(RegexCompileError::UnexpectedSymbolError(c))? as usize;

            next_token = tokens
                .next()
                .ok_or(RegexCompileError::MissingBracketError('}'))?;
        }

        if next_token == Token::ClosingAmountBracket {
            if max_num >= min_num {
                return Ok(AstNode::Between(boxed_prev_node, min_num, max_num));
            } else {
                return Err(RegexCompileError::MinGreaterMaxError);
            }
        }

        Err(RegexCompileError::MissingBracketError('}'))
    }

    fn parse_bracket_char(token: Token) -> AstNode {
        match token {
            Token::Literal(c) => AstNode::Literal(c),
            x => Self::parse_escape(x),
        }
    }

    fn parse_escape(token: Token) -> AstNode {
        match token {
            Token::Dollar => AstNode::Literal('$'),
            Token::Hat => AstNode::Literal('^'),
            Token::Escape => AstNode::Literal('\\'),
            Token::OpeningBracket => AstNode::Literal('['),
            Token::ClosingBracket => AstNode::Literal(']'),
            Token::Star => AstNode::Literal('*'),
            Token::Plus => AstNode::Literal('+'),
            Token::Dot => AstNode::Literal('.'),
            Token::QuestionMark => AstNode::Literal('?'),
            Token::Minus => AstNode::Literal('-'),
            Token::OpeningAmountBracket => AstNode::Literal('{'),
            Token::ClosingAmountBracket => AstNode::Literal('}'),
            Token::Comma => AstNode::Literal(','),
            Token::Literal(c) => Self::parse_escaped_group(c),
        }
    }

    fn parse_escaped_group(literal: char) -> AstNode {
        match literal {
            's' => {
                let nodes = vec![
                    AstNode::Literal(' '),
                    AstNode::Literal('\n'),
                    AstNode::Literal('\t'),
                ];
                AstNode::Bracket(nodes)
            }
            'd' => {
                let mut nodes = vec![];
                for c in '0'..='9' {
                    nodes.push(AstNode::Literal(c));
                }
                AstNode::Bracket(nodes)
            }
            'w' => {
                let mut nodes = vec![AstNode::Literal('_')];
                for c in 'a'..='z' {
                    nodes.push(AstNode::Literal(c));
                }
                for c in 'A'..='Z' {
                    nodes.push(AstNode::Literal(c));
                }
                for c in '0'..='9' {
                    nodes.push(AstNode::Literal(c));
                }
                AstNode::Bracket(nodes)
            }
            'S' => AstNode::NotIn(Box::new(Self::parse_escaped_group('s'))),
            'D' => AstNode::NotIn(Box::new(Self::parse_escaped_group('d'))),
            'W' => AstNode::NotIn(Box::new(Self::parse_escaped_group('w'))),
            x => AstNode::Literal(x),
        }
    }

    // Abstract Sytax Tree -> Deterministic Finite Automaton
    fn codegen(root: AstNode) -> (Vec<DfaNode>, Vec<Transition>, bool, bool) {
        let mut nodes = Vec::new();
        let mut transitions = Vec::new();
        let start_node = DfaNode { accepting: false };
        nodes.push(start_node);

        let mut starts_with_hat = false;
        let mut ends_with_dollar = false;

        if let AstNode::Root(child_nodes) = root {
            if child_nodes[0] == AstNode::Hat {
                starts_with_hat = true;
            }
            if *child_nodes.last().unwrap() == AstNode::Dollar {
                ends_with_dollar = true;
            }

            for node in child_nodes {
                let mut gotten_transitions =
                    Self::get_transitions(&node, nodes.len(), nodes.len() - 1, false);

                if gotten_transitions.is_empty() {
                    continue;
                }

                transitions.append(&mut gotten_transitions);

                let node_count = match node {
                    AstNode::Amount(_, x) | AstNode::MoreThan(_, x) | AstNode::Between(_, _, x) => {
                        x
                    }
                    _ => 1,
                };

                for _ in 0..node_count {
                    let dfa_node = DfaNode { accepting: false };
                    nodes.push(dfa_node);
                }
            }
        }

        let last_index = nodes.len() - 1;

        let end_node = DfaNode { accepting: true };
        nodes.push(end_node);

        let mut new_transitions = Vec::new();
        let mut transitions_to_remove = Vec::new();

        for (i, (t_start, _, t_end)) in transitions
            .iter()
            .enumerate()
            .filter(|(_, (_, c, _))| *c == TransitionFilter::None)
            .rev()
        {
            transitions_to_remove.push(i);

            if let TransitionTarget::State(t_end) = *t_end {
                if nodes[t_end].accepting {
                    nodes[*t_start].accepting = true;
                }

                let mut new = transitions
                    .iter()
                    .filter(|(s, _, e)| *s == t_start + 1 && *e == TransitionTarget::State(t_end))
                    .map(|(s, c, e)| (s - 1, *c, *e))
                    .collect::<Vec<Transition>>();

                new_transitions.append(&mut new);
            }
        }

        for ttr in transitions_to_remove {
            transitions.remove(ttr);
        }

        transitions.append(&mut new_transitions);

        nodes.remove(last_index + 1);

        nodes[last_index].accepting = true;

        (nodes, transitions, starts_with_hat, ends_with_dollar)
    }

    fn get_transitions(
        node: &AstNode,
        self_index: usize,
        prev_index: usize,
        to_fail: bool,
    ) -> Vec<Transition> {
        match node {
            AstNode::Literal(char) => vec![(
                prev_index,
                TransitionFilter::Char(*char),
                Self::get_transition_target(self_index, to_fail),
            )],
            AstNode::Star(child) => {
                let mut fns = vec![];
                fns.append(&mut Self::get_transitions(
                    child, self_index, prev_index, to_fail,
                ));
                fns.append(&mut Self::get_transitions(
                    child, self_index, self_index, to_fail,
                ));
                fns.push((
                    self_index - 1,
                    TransitionFilter::None,
                    Self::get_transition_target(self_index + 1, to_fail),
                ));
                fns
            }
            AstNode::Plus(child) => {
                let mut fns = vec![];
                fns.append(&mut Self::get_transitions(
                    child, self_index, prev_index, to_fail,
                ));
                fns.append(&mut Self::get_transitions(
                    child, self_index, self_index, to_fail,
                ));
                fns
            }
            AstNode::Dot => vec![(
                prev_index,
                TransitionFilter::All,
                Self::get_transition_target(self_index, to_fail),
            )],
            AstNode::Bracket(childs) => {
                let mut fns = vec![];
                for child in childs {
                    fns.append(&mut Self::get_transitions(
                        child, self_index, prev_index, to_fail,
                    ))
                }
                fns
            }
            AstNode::QuestionMark(child) => {
                let mut fns = vec![];
                fns.append(&mut Self::get_transitions(
                    child, self_index, prev_index, to_fail,
                ));
                fns.push((
                    self_index - 1,
                    TransitionFilter::None,
                    Self::get_transition_target(self_index + 1, to_fail),
                ));
                fns
            }
            AstNode::Amount(child, amount) => {
                let mut fns = vec![];
                for i in 0..*amount {
                    fns.append(&mut Self::get_transitions(
                        child,
                        self_index + i,
                        prev_index + i,
                        to_fail,
                    ))
                }
                fns
            }
            AstNode::MoreThan(child, min_amount) => {
                let mut fns = vec![];
                for i in 0..*min_amount {
                    fns.append(&mut Self::get_transitions(
                        child,
                        self_index + i,
                        prev_index + i,
                        to_fail,
                    ))
                }
                fns.append(&mut Self::get_transitions(
                    child,
                    self_index + min_amount - 1,
                    self_index + min_amount - 1,
                    to_fail,
                ));
                fns
            }
            AstNode::Between(child, min_amount, max_amount) => {
                let mut fns = vec![];
                for i in 0..*max_amount {
                    fns.append(&mut Self::get_transitions(
                        child,
                        self_index + i,
                        prev_index + i,
                        to_fail,
                    ));

                    if i >= min_amount - 1 && i < max_amount - 1 {
                        fns.push((
                            self_index + i,
                            TransitionFilter::None,
                            Self::get_transition_target(self_index + max_amount, to_fail),
                        ));
                    }
                }
                fns
            }
            AstNode::NotIn(child) => {
                let mut fns = vec![];
                fns.append(&mut Self::get_transitions(
                    child, self_index, prev_index, true,
                ));
                fns.push((
                    prev_index,
                    TransitionFilter::All,
                    TransitionTarget::State(self_index),
                ));
                fns
            }
            AstNode::Dollar => vec![],
            AstNode::Hat => vec![],
            AstNode::Root(_) => unreachable!(),
        }
    }

    fn get_transition_target(state_target: usize, to_fail: bool) -> TransitionTarget {
        return if to_fail {
            TransitionTarget::Fail
        } else {
            TransitionTarget::State(state_target)
        };
    }

    pub fn verify(&self, input: &str) -> bool {
        let mut state = 0;
        let mut chars = input.chars().peekable();

        while let Some(char) = chars.next() {
            if !self.ends_with_dollar && self.dfa_nodes[state].accepting {
                return true;
            }

            let direct_match = self
                .dfa_transitions
                .get(&(state, TransitionFilter::Char(char)));
            let indirect_match = self.dfa_transitions.get(&(state, TransitionFilter::All));

            match direct_match {
                Some(end) if indirect_match.is_none() || Some(&char) != chars.peek() => {
                    match *end {
                        TransitionTarget::State(end) => state = end,
                        TransitionTarget::Fail => {
                            if self.starts_with_hat {
                                return false;
                            } else {
                                state = 0
                            }
                        }
                    }
                }
                _ => match indirect_match {
                    Some(end) => {
                        // Other case can not exist anyway
                        if let TransitionTarget::State(end) = *end {
                            state = end;
                        }
                    }
                    None => {
                        if self.starts_with_hat {
                            return false;
                        } else {
                            state = 0
                        }
                    }
                },
            };
        }
        self.dfa_nodes[state].accepting
    }

    fn pprint_ast(node: &AstNode, indentation_level: usize) {
        print!("{}", "  ".repeat(indentation_level));
        match node {
            AstNode::Root(childs) => {
                println!("Root:");
                for child in childs {
                    Self::pprint_ast(child, indentation_level + 1)
                }
                println!();
            }
            AstNode::Star(child) => {
                println!("Star:");
                Self::pprint_ast(child, indentation_level + 1)
            }
            AstNode::Plus(child) => {
                println!("Plus:");
                Self::pprint_ast(child, indentation_level + 1)
            }
            AstNode::Dot => {
                println!("Dot");
            }
            AstNode::Bracket(childs) => {
                println!("Bracket:");
                for child in childs {
                    Self::pprint_ast(child, indentation_level + 1)
                }
            }
            AstNode::QuestionMark(child) => {
                println!("QuestionMark:");
                Self::pprint_ast(child, indentation_level + 1)
            }
            AstNode::Dollar => {
                println!("Dollar");
            }
            AstNode::Hat => {
                println!("Hat");
            }
            AstNode::Amount(child, amount) => {
                println!("Amount ({amount}):");
                Self::pprint_ast(child, indentation_level + 1)
            }
            AstNode::MoreThan(child, amount) => {
                println!("MoreThan ({amount}):");
                Self::pprint_ast(child, indentation_level + 1)
            }
            AstNode::Between(child, min_amount, max_amount) => {
                println!("Between ({min_amount} to {max_amount}):");
                Self::pprint_ast(child, indentation_level + 1)
            }
            AstNode::NotIn(child) => {
                println!("NotIn:");
                Self::pprint_ast(child, indentation_level + 1)
            }
            AstNode::Literal(char) => {
                println!("Literal '{char}'");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Regex, RegexCompileError};

    #[test]
    fn empty_regex_fails() {
        let regex = Regex::new("");

        assert_eq!(regex, Err(RegexCompileError::EmptyError));
    }

    #[test]
    fn simple_regex_works() {
        let regex = Regex::new("abc").unwrap();

        assert!(regex.verify("There must be abc in here"));
        assert!(!regex.verify("No ab followed by c in here"));
    }

    #[test]
    fn simple_regex_with_start_and_end_works() {
        let regex = Regex::new("^abc$").unwrap();

        assert!(regex.verify("abc"));
        assert!(!regex.verify("aabc"));
        assert!(!regex.verify("abcc"));
    }

    #[test]
    fn end_works() {
        let regex = Regex::new("a$").unwrap();

        assert!(regex.verify("this end in a"));
        assert!(!regex.verify("this has an a but ends in b"));
    }

    #[test]
    fn escaped_characters_work() {
        let regex = Regex::new("\\.").unwrap();

        assert!(regex.verify("."));
        assert!(!regex.verify("a"));
    }

    #[test]
    fn number_group_works() {
        let regex = Regex::new("\\d").unwrap();

        assert!(regex.verify("1"));
        assert!(regex.verify("9"));
        assert!(!regex.verify("a"));
    }

    #[test]
    fn star_works() {
        let regex = Regex::new("a*").unwrap();

        assert!(regex.verify(""));
        assert!(regex.verify("a"));
        assert!(regex.verify("aa"));
        assert!(regex.verify("b"));
    }

    #[test]
    fn plus_works() {
        let regex = Regex::new("a+").unwrap();

        assert!(!regex.verify(""));
        assert!(regex.verify("a"));
        assert!(regex.verify("aa"));
        assert!(!regex.verify("b"));
    }

    #[test]
    fn question_mark_works() {
        let regex = Regex::new("^a?$").unwrap();

        assert!(regex.verify(""));
        assert!(regex.verify("a"));
        assert!(!regex.verify("aa"));
    }

    #[test]
    fn matching_groups_work() {
        let regex = Regex::new("^[ab]$").unwrap();

        assert!(regex.verify("a"));
        assert!(regex.verify("b"));
        assert!(!regex.verify("c"));
    }

    #[test]
    fn uncompleted_matching_group_fails() {
        let regex = Regex::new("[ab");

        assert_eq!(regex, Err(RegexCompileError::MissingBracketError(']')));
    }

    #[test]
    fn ranges_work() {
        let regex = Regex::new("^[A-Z]$").unwrap();

        assert!(regex.verify("A"));
        assert!(regex.verify("T"));
        assert!(!regex.verify("1"));
    }

    #[test]
    fn multiple_ranges_work() {
        let regex = Regex::new("^[a-zA-Z]$").unwrap();

        assert!(regex.verify("t"));
        assert!(regex.verify("T"));
        assert!(!regex.verify("1"));
    }

    #[test]
    fn set_amount_works() {
        let regex = Regex::new("^a{3}$").unwrap();

        assert!(regex.verify("aaa"));
        assert!(!regex.verify("aa"));
        assert!(!regex.verify("aaaa"));
    }

    #[test]
    fn more_than_works() {
        let regex = Regex::new("^a{3,}$").unwrap();

        assert!(regex.verify("aaa"));
        assert!(regex.verify("aaaa"));
        assert!(!regex.verify("aa"));
    }

    #[test]
    fn between_works() {
        let regex = Regex::new("^a{3,6}$").unwrap();

        assert!(regex.verify("aaa"));
        assert!(regex.verify("aaaaaa"));
        assert!(!regex.verify("aa"));
        assert!(!regex.verify("aaaaaaa"));
    }

    #[test]
    fn not_in_works() {
        let regex = Regex::new("^[^a-z]$").unwrap();

        assert!(regex.verify("A"));
        assert!(!regex.verify("a"));
    }

    #[test]
    fn not_in_digits_works() {
        let regex = Regex::new("^\\D*$").unwrap();

        assert!(regex.verify("abc"));
        assert!(!regex.verify("a1c"));
    }

    #[test]
    fn complex_regex_works() {
        let regex = Regex::new("^https?://\\w+\\.?[a-zA-Z]+").unwrap();

        assert!(regex.verify("https://google.com"));
        assert!(regex.verify("https://twitch.tv"));
        assert!(!regex.verify("Meine Webseite haha: http://localhost"));
    }
}
