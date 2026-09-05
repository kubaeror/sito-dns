//! Verdicts and matching metadata for the filtering pipeline.

use serde::{Deserialize, Serialize};

/// Reference to a filter rule that triggered an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRef {
    pub list_name: Option<String>,
    pub line_number: Option<usize>,
    pub rule_text: String,
    #[serde(default)]
    pub via_cname: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cname_target: Option<String>,
}

impl RuleRef {
    pub fn new(rule_text: impl Into<String>) -> Self {
        Self {
            list_name: None,
            line_number: None,
            rule_text: rule_text.into(),
            via_cname: false,
            cname_target: None,
        }
    }

    #[must_use]
    pub fn with_source(mut self, list_name: impl Into<String>, line: usize) -> Self {
        self.list_name = Some(list_name.into());
        self.line_number = Some(line);
        self
    }

    #[must_use]
    pub fn with_via_cname(mut self, via_cname: bool) -> Self {
        self.via_cname = via_cname;
        self
    }

    #[must_use]
    pub fn with_cname_target(mut self, target: impl Into<String>) -> Self {
        self.cname_target = Some(target.into());
        self
    }
}

/// Reason why a request was blocked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockReason {
    Rule(RuleRef),
    Parental,
    Service(String),
    AntiDohBypass,
}

/// Action to perform when rewriting a DNS query or response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RewriteAction {
    SynthesizeAnswer,
    DnsRewrite {
        rcode: String,
        rtype: Option<String>,
        value: Option<String>,
    },
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
