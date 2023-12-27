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

#[derive(Debug)]
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

#[derive(Debug)]
pub enum RegexCompileError {
    MissingBracketError(char),
    UnexpectedSymbolError(char),
    EmptyError,
    SymbolAfterDollarError,
    DanglingModifierError,
}

#[derive(Debug)]
pub struct Regex {
    dfa_nodes: Vec<DfaNode>,
    dfa_transitions: HashMap<(usize, TransitionFilter), usize>,
    starts_with_hat: bool,
}

impl Display for Regex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

        let (dfa_nodes, dfa_transitions, starts_with_hat) = Self::codegen(ast);

        Ok(Regex {
            dfa_nodes,
            dfa_transitions: HashMap::from_iter(
                dfa_transitions.iter().map(|(s, t, e)| ((*s, *t), *e)),
            ),
            starts_with_hat,
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

        if !has_dollar {
            root_vec.push(AstNode::Star(Box::new(AstNode::Dot)));
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
            Token::Escape => Ok(Self::parse_escape(rest_tokens.next().unwrap())),
            Token::Literal(c) => Ok(AstNode::Literal(c)),
            Token::ClosingBracket => Err(RegexCompileError::UnexpectedSymbolError('}')),
            Token::Hat => Err(RegexCompileError::UnexpectedSymbolError('^')),
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
        for token in tokens {
            let new_node = match token {
                Token::Literal(c) => AstNode::Literal(c),
                Token::ClosingBracket => return Ok(AstNode::Bracket(bracket_chars)),
                x => Self::parse_escape(x),
            };
            bracket_chars.push(new_node)
        }
        Err(RegexCompileError::MissingBracketError('}'))
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
                    let nodes = vec![
                        AstNode::Literal('1'),
                        AstNode::Literal('2'),
                        AstNode::Literal('3'),
                        AstNode::Literal('4'),
                        AstNode::Literal('5'),
                        AstNode::Literal('6'),
                        AstNode::Literal('7'),
                        AstNode::Literal('8'),
                        AstNode::Literal('9'),
                        AstNode::Literal('0'),
                    ];
                    AstNode::Bracket(nodes)
                }
                x => AstNode::Literal(x),
            },
        }
    }

    // Abstract Sytax Tree -> Deterministic Finite Automaton
    fn codegen(root: AstNode) -> (Vec<DfaNode>, Vec<Transition>, bool) {
        let mut nodes = Vec::new();
        let mut transitions = Vec::new();
        let start_node = DfaNode { accepting: false };
        nodes.push(start_node);

        let mut starts_with_hat = false;
        match root {
            AstNode::Root(child_nodes) => {
                if child_nodes[0] == AstNode::Hat {
                    starts_with_hat = true;
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
            _ => panic!(),
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

        (nodes, transitions, starts_with_hat)
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
    use crate::Regex;

    #[test]
    fn it_works() {
        let regex = Regex::new("^https?://.+\\.?.+").unwrap();

        assert_eq!(regex.verify("https://google.com"), true);
        assert_eq!(regex.verify("https://twitch.tv"), true);
        assert_eq!(regex.verify("Meine Webseite haha: http://localhost"), false);

        let regex = Regex::new("\\d+").unwrap();

        assert_eq!(regex.verify("Ich bin 19 Jahre alt!"), true);
        assert_eq!(regex.verify(""), false);
    }
}