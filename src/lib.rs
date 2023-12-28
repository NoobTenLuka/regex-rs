use std::{collections::HashMap, fmt::Display};

#[derive(PartialEq, Eq)]
enum Token {
    Star,
    Plus,
    Dot,
    OpeningBracket,
    ClosingBracket,
    Escape,
    QuestionMark,
    Dollar,
    Hat,
    Minus,
    Literal(char),
}

#[derive(PartialEq, Eq, Debug)]
enum AstNode {
    Root(Vec<AstNode>),
    Star(Box<AstNode>),
    Plus(Box<AstNode>),
    QuestionMark(Box<AstNode>),
    Dot,
    Bracket(Vec<AstNode>),
    Dollar,
    Hat,
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

type Transition = (usize, TransitionFilter, usize);

#[derive(Debug, PartialEq, Eq)]
pub enum RegexCompileError {
    MissingSymbolError,
    MissingBracketError(char),
    UnexpectedSymbolError(char),
    EmptyError,
    SymbolAfterDollarError,
    DanglingModifierError,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Regex {
    dfa_nodes: Vec<DfaNode>,
    dfa_transitions: HashMap<(usize, TransitionFilter), usize>,
    starts_with_hat: bool,
    ends_with_dollar: bool,
}

impl Display for Regex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Starts with hat: {:?}", self.starts_with_hat)?;
        writeln!(f, "Ends with dollar: {:?}", self.ends_with_dollar)?;

        for (i, node) in self.dfa_nodes.iter().enumerate() {
            let to_self: Vec<(&(usize, TransitionFilter), &usize)> = self
                .dfa_transitions
                .iter()
                .filter(|((start, _), end)| *start == i && **end == i)
                .collect();

            let to_next = self
                .dfa_transitions
                .iter()
                .filter(|((start, _), end)| *start == i && **end == i + 1);

            let to_second_next = self
                .dfa_transitions
                .iter()
                .filter(|((start, _), end)| *start == i && **end == i + 2);

            if node.accepting {
                write!(f, "A")?;
            }

            write!(f, "({i:0>3})")?;
            if !to_self.is_empty() {
                write!(f, " ⮌")?;
            }
            for x in to_self {
                write!(f, " {:?}", x.0 .1)?;
            }
            writeln!(f)?;

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
            '?' => Token::QuestionMark,
            '\\' => Token::Escape,
            '$' => Token::Dollar,
            '^' => Token::Hat,
            '-' => Token::Minus,
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
            Token::Star | Token::QuestionMark | Token::Plus => {
                Self::parse_modifier(token, root_vec)
            }
            Token::Dot => Ok(AstNode::Dot),
            Token::OpeningBracket => Self::parse_bracket(rest_tokens),
            Token::Escape => Ok(Self::parse_escape(
                rest_tokens
                    .next()
                    .ok_or(RegexCompileError::MissingSymbolError)?,
            )),
            Token::Literal(c) => Ok(AstNode::Literal(c)),
            Token::ClosingBracket => Err(RegexCompileError::UnexpectedSymbolError('}')),
            Token::Hat => Err(RegexCompileError::UnexpectedSymbolError('^')),
            Token::Minus => Err(RegexCompileError::UnexpectedSymbolError('-')),
            Token::Dollar => {
                *has_dollar = true;
                Ok(AstNode::Dollar)
            }
        }
    }

    fn parse_modifier(
        token: Token,
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
        ) {
            return Err(RegexCompileError::DanglingModifierError);
        }

        let boxed_prev_node = Box::new(previous_node);

        Ok(match token {
            Token::Star => AstNode::Star(boxed_prev_node),
            Token::Plus => AstNode::Plus(boxed_prev_node),
            Token::QuestionMark => AstNode::QuestionMark(boxed_prev_node),
            _ => unreachable!(),
        })
    }

    fn parse_bracket(
        tokens: &mut impl Iterator<Item = Token>,
    ) -> Result<AstNode, RegexCompileError> {
        let mut bracket_chars = Vec::new();
        while let Some(token) = tokens.next() {
            match token {
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
                Token::ClosingBracket => return Ok(AstNode::Bracket(bracket_chars)),
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
            Token::Literal(c) => match c {
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
                x => AstNode::Literal(x),
            },
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
                    Self::get_transitions(&node, nodes.len(), nodes.len() - 1);

                if gotten_transitions.is_empty() {
                    continue;
                }

                transitions.append(&mut gotten_transitions);

                let dfa_node = DfaNode { accepting: false };
                nodes.push(dfa_node);
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

            if nodes[*t_end].accepting {
                nodes[*t_start].accepting = true;
            }

            let mut new = transitions
                .iter()
                .filter(|(s, _, e)| *s == t_start + 1 && *e == *t_end)
                .map(|(s, c, e)| (s - 1, *c, *e))
                .collect::<Vec<Transition>>();

            new_transitions.append(&mut new);
        }

        for ttr in transitions_to_remove {
            transitions.remove(ttr);
        }

        transitions.append(&mut new_transitions);

        nodes.remove(last_index + 1);

        nodes[last_index].accepting = true;

        (nodes, transitions, starts_with_hat, ends_with_dollar)
    }

    fn get_transitions(node: &AstNode, self_index: usize, prev_index: usize) -> Vec<Transition> {
        match node {
            AstNode::Literal(char) => vec![(prev_index, TransitionFilter::Char(*char), self_index)],
            AstNode::Star(child) => {
                let mut fns = vec![];
                fns.append(&mut Self::get_transitions(child, self_index, prev_index));
                fns.append(&mut Self::get_transitions(child, self_index, self_index));
                fns.push((self_index - 1, TransitionFilter::None, self_index + 1));
                fns
            }
            AstNode::Plus(child) => {
                let mut fns = vec![];
                fns.append(&mut Self::get_transitions(child, self_index, prev_index));
                fns.append(&mut Self::get_transitions(child, self_index, self_index));
                fns
            }
            AstNode::Dot => vec![(prev_index, TransitionFilter::All, self_index)],
            AstNode::Bracket(childs) => {
                let mut fns = vec![];
                for child in childs {
                    fns.append(&mut Self::get_transitions(child, self_index, prev_index))
                }
                fns
            }
            AstNode::QuestionMark(child) => {
                let mut fns = vec![];
                fns.append(&mut Self::get_transitions(child, self_index, prev_index));
                fns.push((self_index - 1, TransitionFilter::None, self_index + 1));
                fns
            }
            AstNode::Dollar => vec![],
            AstNode::Hat => vec![],
            AstNode::Root(_) => unreachable!(),
        }
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
                    state = *end
                }
                _ => match indirect_match {
                    Some(end) => state = *end,
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
    fn complex_regex_works() {
        let regex = Regex::new("^https?://\\w+\\.?[a-zA-Z]+").unwrap();

        println!("{regex}");

        assert!(regex.verify("https://google.com"));
        assert!(regex.verify("https://twitch.tv"));
        assert!(!regex.verify("Meine Webseite haha: http://localhost"));
    }
}
