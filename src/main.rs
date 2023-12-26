use std::{collections::HashMap, fmt::Display};

enum Token {
    Star,
    Plus,
    Dot,
    OpeningBracket,
    ClosingBracket,
    Escape,
    Literal(char),
}

#[derive(Debug)]
enum AstNode {
    Root(Vec<AstNode>),
    Star(Box<AstNode>),
    Plus(Box<AstNode>),
    Dot,
    Bracket(Vec<AstNode>),
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
pub struct Regex {
    dfa_nodes: Vec<DfaNode>,
    dfa_transitions: HashMap<(usize, TransitionFilter), usize>,
}

impl Display for Regex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, node) in self.dfa_nodes.iter().enumerate() {
            let to_self: Vec<(&(usize, TransitionFilter), &usize)> = self
                .dfa_transitions
                .iter()
                .filter(|((start, _), end)| *start == i && **end == i)
                .collect();

            let mut to_next = self
                .dfa_transitions
                .iter()
                .filter(|((start, _), end)| *start == i && **end == i + 1);

            let mut to_second_next = self
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

            while let Some(x) = to_next.next() {
                writeln!(f, "  ↓ {:?}", x.0 .1)?;
            }

            while let Some(x) = to_second_next.next() {
                writeln!(f, "  2  ↓ {:?}", x.0 .1)?;
            }
        }

        Ok(())
    }
}

impl Regex {
    pub fn new(regex: &str) -> Self {
        let mut token_stream = Self::lex(regex);

        let ast = Self::parse(&mut token_stream);

        Self::pprint_ast(&ast, 0);

        let (dfa_nodes, dfa_transitions) = Self::codegen(ast);

        Regex {
            dfa_nodes,
            dfa_transitions: HashMap::from_iter(
                dfa_transitions.iter().map(|(s, t, e)| ((*s, *t), *e)),
            ),
        }
    }

    // Input String -> Token Stream
    fn lex(source: &str) -> impl Iterator<Item = Token> + '_ {
        source.chars().map(|c| match c {
            '*' => Token::Star,
            '+' => Token::Plus,
            '.' => Token::Dot,
            '[' => Token::OpeningBracket,
            ']' => Token::ClosingBracket,
            '\\' => Token::Escape,
            x => Token::Literal(x),
        })
    }

    // Token Stream -> Abstract Syntax Tree
    fn parse(tokens: &mut impl Iterator<Item = Token>) -> AstNode {
        let mut root_vec = Vec::new();

        while let Some(token) = tokens.next() {
            let new_node = match token {
                Token::Star => AstNode::Star(Box::new(root_vec.pop().unwrap())),
                Token::Plus => AstNode::Plus(Box::new(root_vec.pop().unwrap())),
                Token::Dot => AstNode::Dot,
                Token::OpeningBracket => Self::parse_bracket(tokens),
                Token::Escape => Self::parse_escape(tokens.next().unwrap()),
                Token::Literal(c) => AstNode::Literal(c),
                _ => panic!(),
            };

            root_vec.push(new_node);
        }

        AstNode::Root(root_vec)
    }

    fn parse_bracket(tokens: &mut impl Iterator<Item = Token>) -> AstNode {
        let mut bracket_chars = Vec::new();
        while let Some(token) = tokens.next() {
            let new_node = match token {
                Token::Literal(c) => AstNode::Literal(c),
                Token::ClosingBracket => return AstNode::Bracket(bracket_chars),
                Token::OpeningBracket => AstNode::Literal('['),
                Token::Dot => AstNode::Literal('.'),
                Token::Star => AstNode::Literal('*'),
                Token::Plus => AstNode::Literal('+'),
                Token::Escape => AstNode::Literal('\\'),
            };
            bracket_chars.push(new_node)
        }
        panic!()
    }

    fn parse_escape(token: Token) -> AstNode {
        match token {
            Token::Escape => AstNode::Literal('\\'),
            Token::OpeningBracket => AstNode::Literal('['),
            Token::ClosingBracket => AstNode::Literal(']'),
            Token::Star => AstNode::Literal('*'),
            Token::Plus => AstNode::Literal('+'),
            Token::Dot => AstNode::Literal('.'),
            Token::Literal(c) => match c {
                's' => {
                    let mut nodes = vec![];
                    nodes.push(AstNode::Literal(' '));
                    nodes.push(AstNode::Literal('\n'));
                    nodes.push(AstNode::Literal('\t'));
                    AstNode::Bracket(nodes)
                }
                'd' => {
                    let mut nodes = vec![];
                    nodes.push(AstNode::Literal('1'));
                    nodes.push(AstNode::Literal('2'));
                    nodes.push(AstNode::Literal('3'));
                    nodes.push(AstNode::Literal('4'));
                    nodes.push(AstNode::Literal('5'));
                    nodes.push(AstNode::Literal('6'));
                    nodes.push(AstNode::Literal('7'));
                    nodes.push(AstNode::Literal('8'));
                    nodes.push(AstNode::Literal('9'));
                    nodes.push(AstNode::Literal('0'));
                    AstNode::Bracket(nodes)
                }
                x => AstNode::Literal(x),
            },
        }
    }

    // Abstract Sytax Tree -> Deterministic Finite Automaton
    fn codegen(root: AstNode) -> (Vec<DfaNode>, Vec<Transition>) {
        let mut nodes = Vec::new();
        let mut transitions = Vec::new();
        let start_node = DfaNode { accepting: false };
        nodes.push(start_node);

        match root {
            AstNode::Root(child_nodes) => {
                for node in child_nodes {
                    transitions.append(&mut Self::get_transitions(
                        &node,
                        nodes.len(),
                        nodes.len() - 1,
                    ));
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

        (nodes, transitions)
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
            _ => unreachable!(),
        }
    }

    fn verify(&self, input: &str) -> bool {
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
                    None => return false,
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
            AstNode::Literal(char) => {
                println!("Literal '{char}'");
            }
        }
    }
}

fn main() {
    let regex = Regex::new("https://.+\\..+");

    println!("{regex}");

    println!("{}", regex.verify("https://google.com"));
    println!("{}", regex.verify("https://guten_morgenb"));
    println!("{}", regex.verify("https://aaab"));

    let regex = Regex::new("\\d+");

    println!("{regex}");

    println!("{}", regex.verify("19"));
}
