//! First-run wizard page, form validation, and completion.

#[allow(clippy::wildcard_imports)]
use super::*;

// ---------------------------------------------------------------------------
// Setup Wizard
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct SetupTokenQuery {
    #[serde(default)]
    pub setup_token: Option<String>,
}

pub async fn wizard_page(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Query(params): Query<SetupTokenQuery>,
) -> Response {
    let auth_user = get_session_user(&ctx, &headers);
    let setup_required = ctx.auth_mgr.setup_token_required();

    // WP-0.7 (P1-16): the wizard is a first-boot surface only. After setup an
    // Admin (or a stolen Admin session) must use the account/settings flows,
    // which require re-authentication, instead of resetting the password here.
    if !ctx.auth_mgr.is_first_run() && !setup_required {
        return error_response(
            StatusCode::FORBIDDEN,
            "Setup wizard is only available during first-boot setup.",
        );
    }

    let csrf = get_csrf_token(&ctx, &headers);
    // Only echo a token the requester already supplied; never reveal the
    // stored setup token in the rendered page on its own.
    let setup_token = params.setup_token.unwrap_or_default();

    HtmlTemplate(WizardTemplate {
        is_authenticated: auth_user.is_some(),
        username: auth_user.as_ref().map_or("admin", |u| &u.username),
        user_role: auth_user.as_ref().map_or("", |u| u.role.as_str()),
        active_tab: "wizard",
        version: env!("CARGO_PKG_VERSION"),
        csrf_token: &csrf,
        setup_required,
        setup_token: &setup_token,
    })
    .into_response()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct WizardCompleteForm {
    /// One-time first-boot setup token (required while setup is pending).
    pub setup_token: Option<String>,

    // 1. Administrator account
    pub admin_user: Option<String>,
    pub admin_password: Option<String>,
    pub confirm_password: Option<String>,

    // 2. DNS listeners
    pub bind_ipv4: Option<String>,
    pub bind_ipv6: Option<String>,
    pub port: Option<String>,
    pub dot_port: Option<String>,
    pub doh_port: Option<String>,
    pub doq_port: Option<String>,

    // 3. Upstreams
    pub upstreams: Option<String>,
    pub upstream: Option<String>,
    pub upstream_strategy: Option<String>,
    pub bootstrap: Option<String>,
    pub timeout_ms: Option<String>,

    // 4. Cache & DNSSEC
    pub cache_enabled: Option<String>,
    pub cache_size_mb: Option<String>,
    pub dnssec_mode: Option<String>,
    pub dnssec_validate: Option<String>,

    // 5. Filtering
    pub filtering_enabled: Option<String>,
    pub enable_adblock: Option<String>,
    pub blocking_mode: Option<String>,
    pub cname_cloaking: Option<String>,
    pub list_oisd_big: Option<String>,
    pub list_oisd_small: Option<String>,
    pub list_stevenblack: Option<String>,
    pub list_hagezi: Option<String>,

    // 6. Web panel & stats
    pub web_bind: Option<String>,
    pub web_port: Option<String>,
    pub retention_days: Option<String>,
}

impl WizardCompleteForm {
    pub(crate) fn is_checkbox_checked(val: Option<&str>) -> bool {
        match val {
            Some(v) => {
                let v = v.trim();
                v == "on" || v == "true" || v == "yes" || v == "1"
            }
            None => false,
        }
    }

    pub fn build_config(&self, base: &Config) -> Result<Config, String> {
        let mut cfg = base.clone();
        self.apply_dns_and_upstream(&mut cfg)?;
        self.apply_cache_and_filtering(&mut cfg)?;
        self.apply_web_and_stats(&mut cfg)?;

        // Validate final configuration
        cfg.validate()
            .map_err(|e| format!("Configuration validation failed: {e}"))?;

        Ok(cfg)
    }

    /// Wizard fields for DNS listeners, ports, and upstream resolvers.
    fn apply_dns_and_upstream(&self, cfg: &mut Config) -> Result<(), String> {
        // 2. DNS Listeners
        let v4_present = self.bind_ipv4.is_some();
        let v6_present = self.bind_ipv6.is_some();
        if v4_present || v6_present {
            let mut binds = Vec::new();
            if Self::is_checkbox_checked(self.bind_ipv4.as_deref()) {
                binds.push(IpAddr::from_str("0.0.0.0").unwrap());
            }
            if Self::is_checkbox_checked(self.bind_ipv6.as_deref()) {
                binds.push(IpAddr::from_str("::").unwrap());
            }
            if binds.is_empty() {
                return Err(
                    "At least one DNS bind address (IPv4 or IPv6) must be selected".to_string(),
                );
            }
            cfg.dns.bind = binds;
        }

        if let Some(s) = self
            .port
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cfg.dns.port = s
                .parse::<u16>()
                .map_err(|_| format!("Invalid DNS port: '{s}'"))?;
        }
        if let Some(s) = self
            .dot_port
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cfg.dns.dot_port = s
                .parse::<u16>()
                .map_err(|_| format!("Invalid DoT port: '{s}'"))?;
        }
        if let Some(s) = self
            .doh_port
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cfg.dns.doh_port = s
                .parse::<u16>()
                .map_err(|_| format!("Invalid DoH port: '{s}'"))?;
        }
        if let Some(s) = self
            .doq_port
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cfg.dns.doq_port = s
                .parse::<u16>()
                .map_err(|_| format!("Invalid DoQ port: '{s}'"))?;
        }

        // 3. Upstream Resolvers
        let mut servers = Vec::new();
        if let Some(s) = self
            .upstreams
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            for line in s.lines() {
                for part in line.split(',') {
                    let clean = part.trim();
                    if !clean.is_empty() {
                        servers.push(clean.to_string());
                    }
                }
            }
        }
        if servers.is_empty()
            && let Some(single) = self
                .upstream
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
        {
            servers.push(single.to_string());
        }
        if !servers.is_empty() {
            cfg.upstream.servers = servers;
        }

        if let Some(s) = self
            .upstream_strategy
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            match s.to_ascii_lowercase().as_str() {
                "failover" => cfg.upstream.strategy = UpstreamStrategy::Failover,
                "parallel" => cfg.upstream.strategy = UpstreamStrategy::Parallel,
                "load_balance" | "loadbalance" => {
                    cfg.upstream.strategy = UpstreamStrategy::LoadBalance;
                }
                other => return Err(format!("Invalid upstream strategy: '{other}'")),
            }
        }

        if let Some(s) = self
            .bootstrap
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let mut boots = Vec::new();
            for part in s.split([',', ' ', '\n']) {
                let clean = part.trim();
                if !clean.is_empty() {
                    let ip = IpAddr::from_str(clean)
                        .map_err(|_| format!("Invalid bootstrap IP: '{clean}'"))?;
                    boots.push(ip);
                }
            }
            if !boots.is_empty() {
                cfg.upstream.bootstrap = boots;
            }
        }

        if let Some(s) = self
            .timeout_ms
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cfg.upstream.timeout_ms = s
                .parse::<u64>()
                .map_err(|_| format!("Invalid timeout_ms: '{s}'"))?;
        }

        Ok(())
    }

    /// Wizard fields for cache, DNSSEC, and filtering presets.
    fn apply_cache_and_filtering(&self, cfg: &mut Config) -> Result<(), String> {
        // 4. Cache & DNSSEC
        if self.cache_enabled.is_some() {
            cfg.dns.cache.enabled = Self::is_checkbox_checked(self.cache_enabled.as_deref());
        }
        if let Some(s) = self
            .cache_size_mb
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cfg.dns.cache.size_mb = s
                .parse::<usize>()
                .map_err(|_| format!("Invalid cache_size_mb: '{s}'"))?;
        }
        if let Some(s) = self
            .dnssec_mode
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cfg.dns.dnssec.mode = s.to_string();
        }
        if self.dnssec_validate.is_some() {
            cfg.dns.dnssec.validate = Self::is_checkbox_checked(self.dnssec_validate.as_deref());
        }

        // 5. Filtering & Protection
        if self.filtering_enabled.is_some() {
            cfg.filtering.enabled = Self::is_checkbox_checked(self.filtering_enabled.as_deref());
        } else if self.enable_adblock.is_some() {
            cfg.filtering.enabled = Self::is_checkbox_checked(self.enable_adblock.as_deref());
        }

        if let Some(s) = self
            .blocking_mode
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            match s.to_ascii_lowercase().as_str() {
                "zero_ip" => cfg.filtering.blocking_mode = BlockingMode::ZeroIp,
                "nxdomain" => cfg.filtering.blocking_mode = BlockingMode::Nxdomain,
                "refused" => cfg.filtering.blocking_mode = BlockingMode::Refused,
                "null_rdata" => cfg.filtering.blocking_mode = BlockingMode::NullRdata,
                other => {
                    if let Ok(ip) = IpAddr::from_str(other) {
                        cfg.filtering.blocking_mode = BlockingMode::CustomIp(ip);
                    } else {
                        return Err(format!("Invalid blocking mode: '{other}'"));
                    }
                }
            }
        }

        if self.cname_cloaking.is_some() {
            cfg.filtering.cname_cloaking =
                Self::is_checkbox_checked(self.cname_cloaking.as_deref());
        }

        let mut lists = Vec::new();
        if Self::is_checkbox_checked(self.list_oisd_big.as_deref()) {
            lists.push(FilterListConfig {
                name: "OISD Big".to_string(),
                url: "https://big.oisd.nl".to_string(),
                enabled: true,
                refresh_hours: None,
            });
        }
        if Self::is_checkbox_checked(self.list_oisd_small.as_deref()) {
            lists.push(FilterListConfig {
                name: "OISD Small".to_string(),
                url: "https://small.oisd.nl".to_string(),
                enabled: true,
                refresh_hours: None,
            });
        }
        if Self::is_checkbox_checked(self.list_stevenblack.as_deref()) {
            lists.push(FilterListConfig {
                name: "StevenBlack Hosts".to_string(),
                url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".to_string(),
                enabled: true,
                refresh_hours: None,
            });
        }
        if Self::is_checkbox_checked(self.list_hagezi.as_deref()) {
            lists.push(FilterListConfig {
                name: "Hagezi Pro".to_string(),
                url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt"
                    .to_string(),
                enabled: true,
                refresh_hours: None,
            });
        }

        // If filtering is enabled and no preset lists were specifically checked,
        // preserve existing lists if any, or provide default OISD Big
        if lists.is_empty()
            && cfg.filtering.enabled
            && (self.enable_adblock.is_some() || self.filtering_enabled.is_some())
        {
            if cfg.filtering.lists.is_empty() {
                lists.push(FilterListConfig {
                    name: "OISD Big".to_string(),
                    url: "https://big.oisd.nl".to_string(),
                    enabled: true,
                    refresh_hours: None,
                });
            } else {
                lists.clone_from(&cfg.filtering.lists);
            }
        }
        if !lists.is_empty() {
            cfg.filtering.lists = lists;
        }

        Ok(())
    }

    /// Wizard fields for the web panel and stats retention.
    fn apply_web_and_stats(&self, cfg: &mut Config) -> Result<(), String> {
        // 6. Web Panel & Stats
        let mut web = cfg.get_web_config();
        if let Some(s) = self
            .web_bind
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            web.bind = IpAddr::from_str(s).map_err(|_| format!("Invalid web bind IP: '{s}'"))?;
        }
        if let Some(s) = self
            .web_port
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            web.port = s
                .parse::<u16>()
                .map_err(|_| format!("Invalid web port: '{s}'"))?;
        }
        cfg.set_web_config(web);

        let mut stats = cfg.get_stats_config();
        if let Some(s) = self
            .retention_days
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            stats.retention_days = s
                .parse::<u32>()
                .map_err(|_| format!("Invalid retention_days: '{s}'"))?;
        }
        let stats_value = toml::Value::try_from(stats)
            .map_err(|e| format!("Failed to serialize stats configuration: {e}"))?;
        cfg.stats = Some(stats_value);

        Ok(())
    }
}

/// Credential mutations made by the wizard, kept so a later configuration
/// persistence failure can restore the previous account state.
#[derive(Default)]
pub(crate) struct WizardCredentialUndo {
    pub(crate) restore_password: Option<(String, String)>,
    pub(crate) remove_created_user: Option<String>,
}

impl WizardCredentialUndo {
    pub(crate) async fn rollback(self, ctx: &ServerContext) {
        if let Some((username, previous_hash)) = self.restore_password
            && let Err(e) = ctx
                .auth_mgr
                .restore_user_password_hash(&username, &previous_hash)
                .await
        {
            tracing::error!(
                user = %username,
                error = %e,
                "Failed to roll back the administrator password after a wizard persistence failure"
            );
        }
        if let Some(username) = self.remove_created_user
            && !ctx.auth_mgr.delete_user(&username).await
        {
            tracing::error!(
                user = %username,
                "Failed to remove the wizard-created administrator during rollback"
            );
        }
    }
}

pub async fn wizard_complete_handler(
    State(ctx): State<ServerContext>,
    Extension(hooks): Extension<ApplyHooks>,
    crate::auth::MaybeConnectInfo(peer_addr): crate::auth::MaybeConnectInfo,
    headers: HeaderMap,
    Form(form): Form<WizardCompleteForm>,
) -> Response {
    // Serialize the whole completion. Capturing the token requirement once
    // prevents a request that entered before a concurrent completion from
    // re-reading it as `false` and skipping token validation.
    let _setup_guard = ctx.auth_mgr.lock_setup_completion().await;
    let is_first_run = ctx.auth_mgr.is_first_run();
    let setup_token_required = ctx.auth_mgr.setup_token_required();
    // Bootstrap mode covers both the default-admin first run and deployments
    // with no usable Admin yet (for example only non-admin accounts), which
    // are recoverable only with the setup token.
    let bootstrapping = is_first_run || setup_token_required;
    let auth_user = get_session_user(&ctx, &headers);
    let is_admin = auth_user.as_ref().is_some_and(|u| u.role == Role::Admin);

    // WP-0.7 (P1-16): completing the wizard mutates the administrator password.
    // It must never be reachable after setup, even for a valid Admin session;
    // password changes then go through the re-authenticated account flow.
    if !bootstrapping {
        return error_response(
            StatusCode::FORBIDDEN,
            "Setup wizard is only available during first-boot setup.",
        );
    }

    // Bootstrap completion requires the one-time setup token (authenticated
    // admins and in-memory test managers without a provisioned token are
    // exempt). The requirement was captured under the completion lock.
    if setup_token_required && !is_admin {
        let config = ctx.config.load();
        let trusted_proxies = config.get_web_config().trusted_proxies.clone();
        drop(config);
        let client_ip = resolve_client_ip(peer_addr, &headers, &trusted_proxies);
        let candidate = form
            .setup_token
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty());
        match ctx.auth_mgr.validate_setup_token(candidate, &client_ip) {
            crate::auth::SetupTokenStatus::Valid => {}
            crate::auth::SetupTokenStatus::RateLimited => {
                return error_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many invalid setup token attempts. Try again later.",
                );
            }
            _ => {
                return error_response(
                    StatusCode::FORBIDDEN,
                    "First-boot setup token required (see server logs).",
                );
            }
        }
    }

    let admin_user = match form.admin_user.as_deref().map(str::trim) {
        Some("") => {
            return (
                StatusCode::BAD_REQUEST,
                "Invalid username: cannot be empty.",
            )
                .into_response();
        }
        Some(u) => u,
        None => "admin",
    };

    if admin_user.contains(|c: char| c.is_whitespace() || c.is_control()) {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid username: cannot contain whitespace or control characters.",
        )
            .into_response();
    }

    let admin_pass_input = form.admin_password.as_deref().map_or("", str::trim);
    let confirm_pass_input = form.confirm_password.as_deref().map_or("", str::trim);

    let effective_password = if admin_pass_input.is_empty() {
        // Never allow completing setup with the default bootstrap password.
        return (
            StatusCode::BAD_REQUEST,
            "Invalid password: a non-default administrator password is required.",
        )
            .into_response();
    } else {
        if admin_pass_input.len() < 8 {
            return (
                StatusCode::BAD_REQUEST,
                "Invalid username or password: password must be at least 8 characters long.",
            )
                .into_response();
        }
        if !confirm_pass_input.is_empty() && confirm_pass_input != admin_pass_input {
            return (StatusCode::BAD_REQUEST, "Passwords do not match.").into_response();
        }
        if admin_pass_input.contains(|c: char| c.is_whitespace() || c.is_control()) {
            return (
                StatusCode::BAD_REQUEST,
                "Invalid password: cannot contain whitespace or control characters.",
            )
                .into_response();
        }
        if admin_pass_input.eq_ignore_ascii_case("adminadmin") {
            return (
                StatusCode::BAD_REQUEST,
                "Invalid password: the default password is not allowed.",
            )
                .into_response();
        }
        admin_pass_input
    };

    // A wizard completion may only target an Admin account. Updating the
    // password of an existing non-Admin would let setup finish with a
    // non-privileged account (and could leave `adminadmin` active).
    if ctx.auth_mgr.has_user(admin_user) && ctx.auth_mgr.role_of(admin_user) != Some(Role::Admin) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "The selected account exists but is not an administrator.",
        );
    }
    if !bootstrapping && !ctx.auth_mgr.has_user(admin_user) {
        return error_response(StatusCode::BAD_REQUEST, "Username does not exist.");
    }

    let (report, filtering, credential_undo) = match apply_wizard_configuration(
        &ctx,
        &hooks,
        &form,
        admin_user,
        effective_password,
        bootstrapping,
    )
    .await
    {
        Ok(result) => result,
        Err(response) => return response,
    };
    finish_wizard_setup(
        &ctx,
        admin_user,
        bootstrapping,
        credential_undo,
        report,
        filtering,
    )
    .await
}

/// Applies the wizard configuration and persists the administrator credential.
/// On any failure the credential undo log is used so setup remains pending.
#[allow(clippy::result_large_err)]
async fn apply_wizard_configuration(
    ctx: &ServerContext,
    hooks: &ApplyHooks,
    form: &WizardCompleteForm,
    admin_user: &str,
    effective_password: &str,
    bootstrapping: bool,
) -> Result<
    (
        crate::config_apply::AppliedReport,
        sito_core::config::FilteringConfig,
        WizardCredentialUndo,
    ),
    Response,
> {
    let mut credential_undo = WizardCredentialUndo::default();
    let (report, filtering) = {
        let _apply_guard = ctx.lock_config_apply().await;
        let base_cfg = (**ctx.config.load()).clone();
        let new_cfg = match form.build_config(&base_cfg) {
            Ok(cfg) => cfg,
            Err(e) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("Invalid configuration: {e}"),
                )
                    .into_response());
            }
        };

        // Defense in depth: if another writer completed setup while this
        // request waited, do not mutate credentials with a stale bootstrap
        // snapshot. The completion lock should already have prevented this.
        if bootstrapping && ctx.auth_mgr.is_setup_complete() && !ctx.auth_mgr.setup_token_required()
        {
            return Err(error_response(
                StatusCode::CONFLICT,
                "Setup has already been completed.",
            ));
        }

        // Change and persist the administrator credential before the
        // configuration file. Setup must never be persisted with the bootstrap
        // password still active.
        if bootstrapping && !ctx.auth_mgr.has_user(admin_user) {
            if let Err(e) = ctx
                .auth_mgr
                .create_user_persisted(admin_user, effective_password, Role::Admin)
                .await
            {
                tracing::error!(user = %admin_user, error = %e, "Wizard failed to create the administrator");
                return Err(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to persist the administrator password. Setup was not completed.",
                ));
            }
            credential_undo.remove_created_user = Some(admin_user.to_string());
        } else {
            match ctx
                .auth_mgr
                .update_user_password_tracked(admin_user, effective_password)
                .await
            {
                Ok(previous_hash) => {
                    credential_undo.restore_password =
                        previous_hash.map(|hash| (admin_user.to_string(), hash));
                }
                Err(e) => {
                    tracing::error!(user = %admin_user, error = %e, "Wizard failed to update the administrator password");
                    return Err(error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to persist the administrator password. Setup was not completed.",
                    ));
                }
            }
        }

        // Apply first, persist second (WP-4.2): a configuration that cannot be
        // applied never reaches the file. The blocklist fetch is deferred to a
        // background refresh so the wizard request does not download lists
        // synchronously; the DNS listeners are only started after the refresh
        // finished.
        let report = match apply_and_persist_config_locked(
            ctx,
            &new_cfg,
            FilterApply::Deferred,
            hooks.as_dyn(),
        )
        .await
        {
            Ok(report) => report,
            Err(e) => {
                tracing::error!("Failed to apply wizard configuration: {e:?}");
                credential_undo.rollback(ctx).await;
                return Err(error_response(
                    StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                    &format!(
                        "Failed to apply configuration: {}. Setup was not completed.",
                        e.detail
                    ),
                ));
            }
        };
        (report, new_cfg.filtering.clone())
    };
    Ok((report, filtering, credential_undo))
}

/// Removes the bootstrap admin, marks setup complete, and starts the deferred
/// filter refresh. Returns the login redirect.
async fn finish_wizard_setup(
    ctx: &ServerContext,
    admin_user: &str,
    bootstrapping: bool,
    credential_undo: WizardCredentialUndo,
    report: crate::config_apply::AppliedReport,
    filtering: sito_core::config::FilteringConfig,
) -> Response {
    if !report.restart_required.is_empty() {
        tracing::warn!(
            fields = ?report.restart_required,
            "Wizard configuration saved; these settings need a restart to take effect"
        );
    }

    if bootstrapping {
        // Never leave the bootstrap `admin` account active after setup
        // completes. Removing it only after the configuration persist means a
        // failure leaves setup pending instead of half-applied.
        if admin_user != "admin"
            && ctx.auth_mgr.is_default_admin_active()
            && let Err(err) = ctx.auth_mgr.delete_user_checked("admin").await
        {
            tracing::error!(
                error = %err,
                "Wizard could not remove the bootstrap admin account; setup remains pending"
            );
            credential_undo.rollback(ctx).await;
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to remove the bootstrap administrator. Setup was not completed.",
            );
        }
        ctx.auth_mgr.mark_setup_complete();
    }

    // All credential and configuration writes succeeded: only now retire the
    // setup token and let the server leave setup mode.
    ctx.auth_mgr.consume_setup_token();
    ctx.set_setup_pending(false);

    // Queue the blocklist fetch/compile off the request path. When the DNS
    // listeners are still gated (first boot), start them only after the
    // filter engine has the new rules.
    let filter_handle = crate::config_apply::queue_filter_refresh(ctx, filtering);
    match ctx.dns_starter.clone() {
        Some(starter) => {
            tokio::spawn(async move {
                let _ = filter_handle.await;
                if let Err(e) = starter.send(()) {
                    tracing::warn!("Failed to notify DNS listener starter after setup: {e}");
                }
            });
        }
        None => drop(filter_handle),
    }

    Redirect::to("/login").into_response()
}
