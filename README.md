# regex-rs
A RegEx parser, which builds a deterministic finite automaton that verifies strings

## Usage

First install the library, then use it in your code like this

```rust
use regex_rs::Regex;

let regex = Regex::new("^a+bc$").unwrap();

let string_to_verify = "aaaabc";

assert!(regex.verify(string_to_verify));
```

## Features

| Feature  | Description               | Status      |
| -------- | ------------------------- | ----------- |
| `a`      | Single character matching | Implemented |
| `a*`     | Zero or more matching     | Implemented |
| `a+`     | One or more matching      | Implemented |
| `a?`     | Zero or one matching      | Implemented |
| `.`      | All characters matching   | Implemented |
| `\\s`    | Whitespace char matching  | Implemented |
| `\\d`    | Digit matching            | Implemented |
| `\\w`    | Word matching             | Implemented |
| `[ab]`   | Group matching            | Implemented |
| `[a-z]`  | Range group matching      | Implemented |
| `^`      | Start of string           | Implemented |
| `$`      | End of string             | Implemented |
| `\\.`    | Escaped symbols matching  | Implemented |
| `a{3}`   | Exact number matching     | Implemented |
| `a{3,}`  | More-than number matching | Implemented |
| `a{3,6}` | Between numbers matching  | Implemented |
| `[^a-z]` | Not in range matching     | Implemented |
| `\\S`    | Non-whitespace matching   | Implemented |
| `\\D`    | Non-digit matching        | Implemented |
| `\\W`    | Non-word matching         | Implemented |
| `a\|b`   | OR matching               | Planned     |
| `(.*)`   | Capture groups            | Planned     |
