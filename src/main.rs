enum Token {
    Star,
    Literal(char),
}

#[derive(Debug)]
enum AstNode {
    Root(Vec<AstNode>),
    Star(Box<AstNode>),
    Literal(char),
}

#[derive(Debug)]
struct DfaNode {
    accepting: bool,
}

type Transition = (usize, Option<char>, usize);

#[derive(Debug)]
pub struct Regex {
    dfa_nodes: Vec<DfaNode>,
    dfa_transitions: Vec<Transition>,
}

impl Regex {
    pub fn new(regex: &str) -> Self {
        let mut token_stream = Self::lex(regex);

        let ast = Self::parse(&mut token_stream);

        println!("{ast:?}");

        let (dfa_nodes, dfa_transitions) = Self::codegen(ast);

        Regex {
            dfa_nodes,
            dfa_transitions,
        }
    }

    // Input String -> Token Stream
    fn lex(source: &str) -> impl Iterator<Item = Token> + '_ {
        source.chars().map(|c| match c {
            '*' => Token::Star,
            x => Token::Literal(x),
        })
    }

    // Token Stream -> Abstract Syntax Tree
    fn parse(tokens: &mut impl Iterator<Item = Token>) -> AstNode {
        let mut root_vec = Vec::new();

        for token in tokens {
            let new_node = match token {
                Token::Star => AstNode::Star(Box::new(root_vec.pop().unwrap())),
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

        nodes[last_index].accepting = true;

        let end_node = DfaNode { accepting: true };
        nodes.push(end_node);

        (nodes, transitions)
    }

    fn get_transitions(node: &AstNode, self_index: usize, prev_index: usize) -> Vec<Transition> {
        match node {
            AstNode::Literal(char) => vec![(prev_index, Some(*char), self_index)],
            AstNode::Star(child) => {
                let mut fns = vec![(self_index - 1, None, self_index + 1)];
                fns.append(&mut Self::get_transitions(child, self_index, prev_index));
                fns.append(&mut Self::get_transitions(child, self_index, self_index));
                fns
            }
            _ => unreachable!(),
        }
    }

    fn verify(&self, input: &str) -> bool {
        let mut state = 0;

        for char in input.chars() {
            let direct_match = self
                .dfa_transitions
                .iter()
                .find(|(start, filter, _)| *start == state && *filter == Some(char));

            match direct_match {
                Some((_, _, end)) => state = *end,
                None => {
                    let indirect_match = self
                        .dfa_transitions
                        .iter()
                        .find(|(start, filter, _)| *start == state && *filter == None);

                    match indirect_match {
                        Some((_, _, end)) => state = *end,
                        None => return false,
                    };
                }
            };
        }
        self.dfa_nodes[state].accepting
    }
}

fn main() {
    let regex = Regex::new("a");

    println!("{regex:?}");

    println!("{}", regex.verify("aa"));
    println!("{}", regex.verify("b"));
}
