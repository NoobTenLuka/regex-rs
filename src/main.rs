enum Token {
    Star,
    Plus,
    Literal(char),
}

#[derive(Debug)]
enum AstNode {
    Root(Vec<AstNode>),
    Star(Box<AstNode>),
    Plus(Box<AstNode>),
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
            '+' => Token::Plus,
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

        let mut new_transitions = Vec::new();
        let mut transitions_to_remove = Vec::new();

        for (i, (t_start, _, t_end)) in transitions
            .iter()
            .enumerate()
            .filter(|(_, (_, c, _))| *c == None)
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

        (nodes, transitions)
    }

    fn get_transitions(node: &AstNode, self_index: usize, prev_index: usize) -> Vec<Transition> {
        match node {
            AstNode::Literal(char) => vec![(prev_index, Some(*char), self_index)],
            AstNode::Star(child) => {
                let mut fns = vec![];
                fns.append(&mut Self::get_transitions(child, self_index, prev_index));
                fns.append(&mut Self::get_transitions(child, self_index, self_index));
                fns.push((self_index - 1, None, self_index + 1));
                fns
            }
            AstNode::Plus(child) => {
                let mut fns = vec![];
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
                    return false
                }
            };
        }
        self.dfa_nodes[state].accepting
    }
}

fn main() {
    let regex = Regex::new("https://a+b*");

    println!("{regex:?}");

    println!("{}", regex.verify("https://"));
    println!("{}", regex.verify("https://aaaaaa"));
    println!("{}", regex.verify("https://aaabbbbbb"));
}
