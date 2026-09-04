//! Verdicts and matching metadata for the filtering pipeline.

use serde::{Deserialize, Serialize};

/// Reference to a filter rule that triggered an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRef {
    pub list_name: Option<String>,
    pub line_number: Option<usize>,
    pub rule_text: String,
}

impl RuleRef {
    pub fn new(rule_text: impl Into<String>) -> Self {
        Self {
            list_name: None,
            line_number: None,
            rule_text: rule_text.into(),
        }
    }

    #[must_use]
    pub fn with_source(mut self, list_name: impl Into<String>, line: usize) -> Self {
        self.list_name = Some(list_name.into());
        self.line_number = Some(line);
        self
    }
}

/// Reason why a request was blocked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockReason {
    Rule(RuleRef),
    Parental,
    Service(String),
}

/// Action to perform when rewriting a DNS query or response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RewriteAction {
    SynthesizeAnswer,
}

/// The filtering verdict for an incoming query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Allow(Option<RuleRef>),
    Block(BlockReason),
    Rewrite(RewriteAction),
}

impl Verdict {
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Block(_))
    }

    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow(_))
    }
}
