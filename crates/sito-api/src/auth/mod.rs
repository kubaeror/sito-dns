//! Authentication, session management, TOTP, API tokens, and RBAC per sections 12.1 and 12.2.

pub mod client_ip;
pub mod lockout;
pub mod manager;
pub mod password;
pub mod rbac;
pub mod session;
pub mod token;
pub mod totp;

pub use client_ip::{MaybeConnectInfo, resolve_client_ip};
pub use lockout::LockoutTracker;
pub use manager::{AuthManager, LoginResult};
pub use password::{hash_password, verify_password};
pub use rbac::{AuthUser, RequireAdmin, RequireOperator, RequireViewer};
pub use session::{Session, build_clear_session_cookie, build_session_cookie};
pub use token::{ApiTokenMeta, CreateTokenResponse, Role, generate_token, hash_token};
pub use totp::{TotpConfig, TotpSetupResponse};
