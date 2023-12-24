use std::{collections::HashMap, fmt::Display};

enum Token {
    Star,
    Plus,
    Dot,
    Literal(char),
}

#[derive(Debug)]
enum AstNode {
    Root(Vec<AstNode>),
    Star(Box<AstNode>),
    Plus(Box<AstNode>),
    Dot,
    Literal(char),
}

impl Display for AstNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root(childs) => {
                writeln!(f, "Root:")?;
                for child in childs {
                    writeln!(f, "  {child}")?;
                }
            }
            Self::Star(child) => {
                writeln!(f, "Star:")?;
                write!(f, "    {child}")?;
            }
            Self::Plus(child) => {
                writeln!(f, "Plus:")?;
                write!(f, "    {child}")?;
            }
            Self::Dot => {
                write!(f, "Dot")?;
            }
            Self::Literal(char) => {
                write!(f, "Literal '{char}'")?;
            }
        }

        Ok(())
    }
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
            let to_self = self
                .dfa_transitions
                .iter()
                .find(|((start, _), end)| *start == i && **end == i);

            let to_next = self
                .dfa_transitions
                .iter()
                .find(|((start, _), end)| *start == i && **end == i + 1);

            let to_second_next = self
                .dfa_transitions
                .iter()
                .find(|((start, _), end)| *start == i && **end == i + 2);

            if node.accepting {
                write!(f, "A")?;
            }

            write!(f, "({i:0>3})")?;
            match to_self {
                Some(x) => writeln!(f, " ⮌ {:?}", x.1)?,
                None => writeln!(f)?,
            }

            if let Some(x) = to_next {
                writeln!(f, "  ↓ {:?}", x.1)?;
            }

            if let Some(x) = to_second_next {
                writeln!(f, "  2  ↓ {:?}", x.1)?;
            }
        }

        Ok(())
    }
}

impl Regex {
    pub fn new(regex: &str) -> Self {
        let mut token_stream = Self::lex(regex);

        let ast = Self::parse(&mut token_stream);

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
            x => Token::Literal(x),
        })
    }

    // Token Stream -> Abstract Syntax Tree
    fn parse(tokens: &mut impl Iterator<Item = Token>) -> AstNode {
        let mut root_vec = Vec::new();

        for token in tokens {
            let new_node = match token {
                Token::Star => AstNode::Star(Box::new(root_vec.pop().unwrap())),
                Token::Plus => AstNode::Plus(Box::new(root_vec.pop().unwrap())),
                Token::Dot => AstNode::Dot,
                Token::Literal(c) => AstNode::Literal(c),
            };

            root_vec.push(new_node);
        }

        AstNode::Root(root_vec)
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
}

fn main() {
    let regex = Regex::new("https://.+b");

    println!("{}", regex.verify("https://b"));
    println!("{}", regex.verify("https://guten_morgenb"));
    println!("{}", regex.verify("https://aaab"));
}
