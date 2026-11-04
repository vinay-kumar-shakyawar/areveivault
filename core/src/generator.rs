//! Password and passphrase generation from the OS CSPRNG.
//! `rand`'s `choose`/`gen_range` use rejection sampling, so selection is unbiased.

use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

use crate::{Error, Result};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/~";
const AMBIGUOUS: &str = "Il1O0o|`'\"";

static WORDLIST_RAW: &str = include_str!("../data/eff_large_wordlist.txt");
static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();

fn words() -> &'static [&'static str] {
    WORDS.get_or_init(|| {
        WORDLIST_RAW
            .lines()
            .filter_map(|l| l.split_whitespace().nth(1))
            .collect()
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        PasswordOptions { length: 20, lowercase: true, uppercase: true, digits: true, symbols: true, avoid_ambiguous: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        PassphraseOptions { words: 5, separator: "-".into(), capitalize: true, include_number: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Generated {
    pub value: String,
    pub entropy_bits: f64,
}

pub fn generate_password(opts: &PasswordOptions) -> Result<Generated> {
    if !(4..=128).contains(&opts.length) {
        return Err(Error::Invalid("length must be 4-128".into()));
    }
    let filter = |s: &str| -> Vec<char> {
        s.chars().filter(|c| !(opts.avoid_ambiguous && AMBIGUOUS.contains(*c))).collect()
    };
    let mut classes: Vec<Vec<char>> = Vec::new();
    if opts.lowercase {
        classes.push(filter(LOWER));
    }
    if opts.uppercase {
        classes.push(filter(UPPER));
    }
    if opts.digits {
        classes.push(filter(DIGITS));
    }
    if opts.symbols {
        classes.push(filter(SYMBOLS));
    }
    if classes.is_empty() {
        return Err(Error::Invalid("select at least one character set".into()));
    }
    let all: Vec<char> = classes.iter().flatten().copied().collect();
    let mut rng = rand::rngs::OsRng;

    // One from each selected class (so site rules are satisfied), rest from the union, then shuffle.
    let mut out: Vec<char> = classes.iter().map(|c| *c.choose(&mut rng).unwrap()).collect();
    while out.len() < opts.length {
        out.push(*all.choose(&mut rng).unwrap());
    }
    out.shuffle(&mut rng);
    Ok(Generated {
        value: out.into_iter().collect(),
        entropy_bits: opts.length as f64 * (all.len() as f64).log2(),
    })
}

pub fn generate_passphrase(opts: &PassphraseOptions) -> Result<Generated> {
    if !(3..=20).contains(&opts.words) {
        return Err(Error::Invalid("words must be 3-20".into()));
    }
    let list = words();
    let mut rng = rand::rngs::OsRng;
    let mut parts: Vec<String> = (0..opts.words)
        .map(|_| {
            let w = *list.choose(&mut rng).unwrap();
            if opts.capitalize {
                let mut c = w.chars();
                c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
            } else {
                w.to_string()
            }
        })
        .collect();
    let mut entropy = opts.words as f64 * (list.len() as f64).log2();
    if opts.include_number {
        let i = rng.gen_range(0..parts.len());
        parts[i].push_str(&rng.gen_range(0..10).to_string());
        entropy += (10f64).log2() + (opts.words as f64).log2();
    }
    Ok(Generated { value: parts.join(&opts.separator), entropy_bits: entropy })
}

/// Splits a password into runs for display: letters vs digits vs symbols
/// (brand guide: digits and symbols rendered in the accent color).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CharRun {
    pub kind: &'static str,
    pub text: String,
}

pub fn tokenize(password: &str) -> Vec<CharRun> {
    let kind = |c: char| {
        if c.is_alphabetic() {
            "letter"
        } else if c.is_ascii_digit() {
            "digit"
        } else {
            "symbol"
        }
    };
    let mut runs: Vec<CharRun> = Vec::new();
    for c in password.chars() {
        let k = kind(c);
        match runs.last_mut() {
            Some(r) if r.kind == k => r.text.push(c),
            _ => runs.push(CharRun { kind: k, text: c.to_string() }),
        }
    }
    runs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_loaded() {
        assert_eq!(words().len(), 7776);
        assert_eq!(words()[0], "abacus");
    }

    #[test]
    fn password_respects_options() {
        for _ in 0..200 {
            let g = generate_password(&PasswordOptions::default()).unwrap();
            assert_eq!(g.value.chars().count(), 20);
            assert!(g.value.chars().any(|c| c.is_ascii_lowercase()));
            assert!(g.value.chars().any(|c| c.is_ascii_uppercase()));
            assert!(g.value.chars().any(|c| c.is_ascii_digit()));
            assert!(g.value.chars().any(|c| SYMBOLS.contains(c)));
            assert!(!g.value.chars().any(|c| AMBIGUOUS.contains(c)));
        }
        let digits = generate_password(&PasswordOptions {
            length: 8,
            lowercase: false,
            uppercase: false,
            symbols: false,
            ..Default::default()
        })
        .unwrap();
        assert!(digits.value.chars().all(|c| c.is_ascii_digit()));
        assert!(generate_password(&PasswordOptions { length: 2, ..Default::default() }).is_err());
    }

    #[test]
    fn passphrase_shape() {
        let g = generate_passphrase(&PassphraseOptions::default()).unwrap();
        assert_eq!(g.value.split('-').count(), 5);
        assert!(g.entropy_bits > 64.0);
    }

    #[test]
    fn distribution_is_roughly_uniform() {
        let opts = PasswordOptions {
            length: 64,
            lowercase: false,
            uppercase: false,
            symbols: false,
            avoid_ambiguous: false,
            ..Default::default()
        };
        let mut counts = [0usize; 10];
        for _ in 0..500 {
            for c in generate_password(&opts).unwrap().value.chars() {
                counts[c.to_digit(10).unwrap() as usize] += 1;
            }
        }
        // 32,000 samples, expected 3,200 each; allow a wide but meaningful band.
        assert!(counts.iter().all(|&n| (2800..3600).contains(&n)), "{counts:?}");
    }

    #[test]
    fn tokenize_runs() {
        let r = tokenize("ab12$C");
        assert_eq!(r.iter().map(|r| r.kind).collect::<Vec<_>>(), ["letter", "digit", "symbol", "letter"]);
    }
}
