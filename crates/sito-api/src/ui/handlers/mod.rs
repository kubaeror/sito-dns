//! UI routes, HTMX partial endpoints, and form handlers.
//!
//! Handlers are grouped by page; shared session/CSRF/formatting helpers live in
//! `common`. Every item is re-exported here so the historical
//! `ui::handlers::*` paths and the moved unit tests keep working.

//! UI routes, HTMX partial endpoints, and form handlers.

use axum::extract::{Extension, Form, Path, Query, State};
use axum::http::StatusCode;
use axum::http::header::{HeaderMap, SET_COOKIE};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::net::IpAddr;
use std::str::FromStr;

use crate::auth::manager::{LoginResult, ReauthError, TotpMutationError, UserMutationError};
use crate::auth::rbac::AuthUser;
use crate::auth::resolve_client_ip;
use crate::auth::session::{
    build_clear_csrf_cookie, build_clear_session_cookie, build_csrf_cookie, extract_session_cookie,
};
use crate::auth::token::Role;
use crate::config_apply::{
    ApplyHooks, ConfigFileApplyOutcome, FilterApply, apply_and_persist_config_locked,
    apply_config_document_event,
};
use crate::error::ProblemDetails;
use crate::handlers::auth_handlers::{
    user_mutation_problem, validate_password_policy, validate_username,
};
use crate::models::{AcmeStatus, FilterListDto, StatusResponse};
use crate::probe::probe_upstream_target;
use crate::state::ServerContext;
use crate::ui::templates::{
    AccountTemplate, ClientDiscoveryViewItem, ClientViewItem, ClientsTemplate,
    DashboardStatsPartialTemplate, DashboardTemplate, FilteringTemplate, HtmlTemplate,
    LoginTemplate, QueryLogRowItem, QueryLogRowsPartialTemplate, QueryLogTemplate, RewriteViewItem,
    RewritesTemplate, SettingsTemplate, SystemTemplate, TokenViewItem, TotpSetupView,
    UpstreamViewItem, UpstreamsTemplate, UserViewItem, UsersTemplate, WizardTemplate,
};
use sito_core::FilterEngine;
use sito_core::config::{BlockingMode, Config, FilterListConfig, UpstreamStrategy};
use sito_stats::QueryLogFilter;

mod account;
mod clients;
mod common;
mod dashboard;
mod filtering;
mod login;
mod querylog;
mod rewrites;
mod settings;
mod system;
mod upstreams;
mod users;
mod wizard;

pub use account::*;
pub use clients::*;
pub use common::*;
pub use dashboard::*;
pub use filtering::*;
pub use login::*;
pub use querylog::*;
pub use rewrites::*;
pub use settings::*;
pub use system::*;
pub use upstreams::*;
pub use users::*;
pub use wizard::*;

#[cfg(test)]
mod tests;
