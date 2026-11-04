//! Password strength via zxcvbn, computed in core so every platform agrees.

use serde::{Deserialize, Serialize};

/// Signup requires at least this score for the master password.
pub const MASTER_PASSWORD_MIN_SCORE: u8 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Strength {
    pub score: u8,
    pub guesses_log10: f64,
    pub crack_time: String,
    pub warning: Option<String>,
    pub suggestions: Vec<String>,
}

pub fn estimate(password: &str, user_inputs: &[&str]) -> Strength {
    if password.is_empty() {
        return Strength { score: 0, guesses_log10: 0.0, crack_time: "instant".into(), warning: None, suggestions: vec![] };
    }
    let e = zxcvbn::zxcvbn(password, user_inputs);
    let feedback = e.feedback();
    Strength {
        score: u8::from(e.score()),
        guesses_log10: e.guesses_log10(),
        crack_time: e.crack_times().offline_slow_hashing_1e4_per_second().to_string(),
        warning: feedback.and_then(|f| f.warning()).map(|w| w.to_string()),
        suggestions: feedback
            .map(|f| f.suggestions().iter().map(|s| s.to_string()).collect())
            .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores() {
        assert!(estimate("password", &[]).score < 2);
        assert!(estimate("arevei2024", &["arevei"]).score < MASTER_PASSWORD_MIN_SCORE);
        assert!(estimate("Correct-Horse-Battery-Staple-91", &[]).score >= MASTER_PASSWORD_MIN_SCORE);
        assert_eq!(estimate("", &[]).score, 0);
    }
}
