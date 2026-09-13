//! Authentication, session management, TOTP, API tokens, and RBAC per sections 12.1 and 12.2.

pub mod client_ip;
pub mod lockout;
pub mod manager;
pub mod password;
pub mod rbac;
pub mod session;
pub mod token;
pub mod totp;

pub use client_ip::{MaybeConnectInfo, is_https_request, resolve_client_ip};
pub use lockout::LockoutTracker;
pub use manager::{AuthManager, AuthStorageError, LoginResult, SetupTokenStatus, TotpVerifyResult};
pub use password::{hash_password, verify_password};
pub use rbac::{AuthUser, RequireAdmin, RequireOperator, RequireViewer, authenticate_request};
pub use session::{
    CSRF_COOKIE_NAME, Session, build_clear_csrf_cookie, build_clear_session_cookie,
    build_csrf_cookie, build_session_cookie, extract_csrf_cookie, extract_session_cookie,
};
pub use token::{ApiTokenMeta, CreateTokenResponse, Role, generate_token, hash_token};
pub use totp::{TotpConfig, TotpSetupResponse};
