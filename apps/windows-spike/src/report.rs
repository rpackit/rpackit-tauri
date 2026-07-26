//! Secret-free acceptance report schema.

use std::{
    collections::BTreeMap,
    fs, io,
    path::Path,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};

use rpackit_transport::HostResolution;
use rpackit_transport_testkit::{
    BrowserReport, CollectorSnapshot, ListenerOverlapEvidence, MalformedUpstreamBodyEvidence,
    MalformedUpstreamEvidence, RequestBodyLimitEvidence, ResponseResourceLimitEvidence,
    UpstreamSnapshot, WebSocketRateLimitEvidence,
};
use serde::Serialize;

/// Native cookie evidence. No credential value is retained.
///
/// Separate booleans are intentional because this is a serialized evidence
/// checklist, not application state.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, Serialize)]
pub struct CookieEvidence {
    pub bootstrap_finished: bool,
    pub authenticated_bootstrap_queued: bool,
    pub readback_count_exactly_one: bool,
    pub value_matches: bool,
    pub http_only: bool,
    pub same_site_strict: bool,
    pub path_root: bool,
    pub no_max_age: bool,
    pub session_expiration: bool,
    pub secure_flag_false: bool,
    pub readback_domain: Option<String>,
    pub authenticated_root_finished: bool,
    pub browser_report_received: bool,
    pub clean_recreation_cookie_absent: bool,
}

/// Secret-free cross-process evidence for the forced-crash profile gate.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, Serialize)]
pub struct CrashProfileEvidence {
    pub probe_completed: bool,
    pub producer_paths_scoped_to_system_temp: bool,
    pub producer_spawned: bool,
    pub producer_received_no_secret_input: bool,
    pub producer_cookie_verified_before_crash: bool,
    pub producer_profile_populated_before_crash: bool,
    pub producer_forcibly_terminated: bool,
    pub producer_reaped_after_termination: bool,
    pub graceful_cleanup_sentinel_absent: bool,
    pub control_marker_secret_free: bool,
    pub crashed_profile_recreation_completed: bool,
    pub crashed_profile_cookie_absent: bool,
    pub recreation_webview_destroyed: bool,
    pub crash_profile_directory_removed: bool,
}

impl CrashProfileEvidence {
    fn all_forced_crash_controls_hold(&self) -> bool {
        self.probe_completed
            && self.producer_paths_scoped_to_system_temp
            && self.producer_spawned
            && self.producer_received_no_secret_input
            && self.producer_cookie_verified_before_crash
            && self.producer_profile_populated_before_crash
            && self.producer_forcibly_terminated
            && self.producer_reaped_after_termination
            && self.graceful_cleanup_sentinel_absent
            && self.control_marker_secret_free
            && self.crashed_profile_recreation_completed
            && self.crashed_profile_cookie_absent
            && self.recreation_webview_destroyed
            && self.crash_profile_directory_removed
    }
}

/// Cross-thread counters populated by native `WebView` callbacks.
#[derive(Debug, Default)]
pub(crate) struct BrowserEscapeProbe {
    navigation_block_callbacks: AtomicU32,
    navigation_network_blocks: AtomicU32,
    popup_deny_callbacks: AtomicU32,
    download_cancel_callbacks: AtomicU32,
    external_scheme_guard_attached: AtomicBool,
    external_scheme_native_attempt_queued: AtomicBool,
    external_scheme_events: AtomicU32,
    expected_external_scheme_events: AtomicU32,
    external_scheme_native_events: AtomicU32,
    external_scheme_cancellations: AtomicU32,
    native_hardening_finished: AtomicBool,
    native_hardening_completed: AtomicBool,
    devtools_disabled: AtomicBool,
    browser_accelerators_disabled: AtomicBool,
    default_context_menus_disabled: AtomicBool,
    extension_install_attempted: AtomicBool,
    extension_install_completed: AtomicBool,
    extension_install_rejected_not_supported: AtomicBool,
}

impl BrowserEscapeProbe {
    pub(crate) fn record_navigation_block(&self) {
        self.navigation_block_callbacks
            .fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn record_navigation_network_block(&self) {
        self.navigation_network_blocks
            .fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn record_popup_deny(&self) {
        self.popup_deny_callbacks.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn record_download_cancel(&self) {
        self.download_cancel_callbacks
            .fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn record_external_scheme_guard_attached(&self) {
        self.external_scheme_guard_attached
            .store(true, Ordering::SeqCst);
    }

    pub(crate) fn record_external_scheme_native_attempt(&self, queued: bool) {
        if queued {
            self.external_scheme_native_attempt_queued
                .store(true, Ordering::SeqCst);
        }
    }

    pub(crate) fn record_external_scheme_event(
        &self,
        expected: bool,
        native: bool,
        cancelled: bool,
    ) {
        self.external_scheme_events.fetch_add(1, Ordering::SeqCst);
        if expected {
            self.expected_external_scheme_events
                .fetch_add(1, Ordering::SeqCst);
        }
        if native {
            self.external_scheme_native_events
                .fetch_add(1, Ordering::SeqCst);
        }
        if cancelled {
            self.external_scheme_cancellations
                .fetch_add(1, Ordering::SeqCst);
        }
    }

    pub(crate) fn external_scheme_native_event_count(&self) -> u32 {
        self.external_scheme_native_events.load(Ordering::SeqCst)
    }

    pub(crate) fn record_settings(
        &self,
        devtools_disabled: bool,
        browser_accelerators_disabled: bool,
        default_context_menus_disabled: bool,
    ) {
        self.devtools_disabled
            .store(devtools_disabled, Ordering::SeqCst);
        self.browser_accelerators_disabled
            .store(browser_accelerators_disabled, Ordering::SeqCst);
        self.default_context_menus_disabled
            .store(default_context_menus_disabled, Ordering::SeqCst);
    }

    pub(crate) fn record_extension_attempt(&self) {
        self.extension_install_attempted
            .store(true, Ordering::SeqCst);
    }

    pub(crate) fn record_extension_result(&self, rejected_not_supported: bool) {
        self.extension_install_rejected_not_supported
            .store(rejected_not_supported, Ordering::SeqCst);
        self.extension_install_completed
            .store(true, Ordering::SeqCst);
    }

    pub(crate) fn record_native_hardening_completed(&self, completed: bool) {
        self.native_hardening_completed
            .store(completed, Ordering::SeqCst);
        self.native_hardening_finished.store(true, Ordering::SeqCst);
    }

    pub(crate) fn native_hardening_finished(&self) -> bool {
        self.native_hardening_finished.load(Ordering::SeqCst)
    }

    pub(crate) fn native_hardening_succeeded(&self) -> bool {
        self.native_hardening_finished() && self.native_hardening_completed.load(Ordering::SeqCst)
    }

    pub(crate) fn runtime_attempts_observed(&self) -> bool {
        self.native_hardening_completed.load(Ordering::SeqCst)
            && self.extension_install_completed.load(Ordering::SeqCst)
            && self.navigation_block_callbacks.load(Ordering::SeqCst) == 1
            && self.navigation_network_blocks.load(Ordering::SeqCst) == 1
            && self.popup_deny_callbacks.load(Ordering::SeqCst) == 1
            && self.download_cancel_callbacks.load(Ordering::SeqCst) == 1
            && self
                .external_scheme_native_attempt_queued
                .load(Ordering::SeqCst)
            && self.expected_external_scheme_events.load(Ordering::SeqCst) >= 1
            && self.external_scheme_native_events.load(Ordering::SeqCst) >= 1
            && self.external_scheme_cancellations.load(Ordering::SeqCst)
                == self.external_scheme_events.load(Ordering::SeqCst)
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::fn_params_excessive_bools)]
    pub(crate) fn snapshot(
        &self,
        probe_completed: bool,
        environment_overrides_absent: bool,
        registry_overrides_absent_before_creation: bool,
        registry_overrides_absent_after_creation: bool,
        devtools_active_port_absent: bool,
        download_directory_empty: bool,
        external_scheme_registration_volatile: bool,
        external_scheme_handler_canary_verified: bool,
        external_scheme_handler_canary_absent: bool,
        external_scheme_registration_removed: bool,
    ) -> BrowserEscapeEvidence {
        BrowserEscapeEvidence {
            probe_completed,
            navigation_block_callbacks: self.navigation_block_callbacks.load(Ordering::SeqCst),
            navigation_network_blocks: self.navigation_network_blocks.load(Ordering::SeqCst),
            popup_deny_callbacks: self.popup_deny_callbacks.load(Ordering::SeqCst),
            download_cancel_callbacks: self.download_cancel_callbacks.load(Ordering::SeqCst),
            external_scheme_guard_attached: self
                .external_scheme_guard_attached
                .load(Ordering::SeqCst),
            external_scheme_native_attempt_queued: self
                .external_scheme_native_attempt_queued
                .load(Ordering::SeqCst),
            external_scheme_events: self.external_scheme_events.load(Ordering::SeqCst),
            expected_external_scheme_events: self
                .expected_external_scheme_events
                .load(Ordering::SeqCst),
            external_scheme_native_events: self
                .external_scheme_native_events
                .load(Ordering::SeqCst),
            external_scheme_cancellations: self
                .external_scheme_cancellations
                .load(Ordering::SeqCst),
            native_hardening_completed: self.native_hardening_completed.load(Ordering::SeqCst),
            devtools_disabled: self.devtools_disabled.load(Ordering::SeqCst),
            browser_accelerators_disabled: self
                .browser_accelerators_disabled
                .load(Ordering::SeqCst),
            default_context_menus_disabled: self
                .default_context_menus_disabled
                .load(Ordering::SeqCst),
            extension_install_attempted: self.extension_install_attempted.load(Ordering::SeqCst),
            extension_install_completed: self.extension_install_completed.load(Ordering::SeqCst),
            extension_install_rejected_not_supported: self
                .extension_install_rejected_not_supported
                .load(Ordering::SeqCst),
            environment_overrides_absent,
            registry_overrides_absent_before_creation,
            registry_overrides_absent_after_creation,
            devtools_active_port_absent,
            download_directory_empty,
            external_scheme_registration_volatile,
            external_scheme_handler_canary_verified,
            external_scheme_handler_canary_absent,
            external_scheme_registration_removed,
        }
    }
}

/// Secret-free evidence that browser escape paths were actively attempted and
/// blocked by the real `WebView2` instance.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, Serialize)]
pub struct BrowserEscapeEvidence {
    pub probe_completed: bool,
    pub navigation_block_callbacks: u32,
    pub navigation_network_blocks: u32,
    pub popup_deny_callbacks: u32,
    pub download_cancel_callbacks: u32,
    pub external_scheme_guard_attached: bool,
    pub external_scheme_native_attempt_queued: bool,
    pub external_scheme_events: u32,
    pub expected_external_scheme_events: u32,
    pub external_scheme_native_events: u32,
    pub external_scheme_cancellations: u32,
    pub native_hardening_completed: bool,
    pub devtools_disabled: bool,
    pub browser_accelerators_disabled: bool,
    pub default_context_menus_disabled: bool,
    pub extension_install_attempted: bool,
    pub extension_install_completed: bool,
    pub extension_install_rejected_not_supported: bool,
    pub environment_overrides_absent: bool,
    pub registry_overrides_absent_before_creation: bool,
    pub registry_overrides_absent_after_creation: bool,
    pub devtools_active_port_absent: bool,
    pub download_directory_empty: bool,
    pub external_scheme_registration_volatile: bool,
    pub external_scheme_handler_canary_verified: bool,
    pub external_scheme_handler_canary_absent: bool,
    pub external_scheme_registration_removed: bool,
}

impl BrowserEscapeEvidence {
    fn all_browser_escape_controls_hold(
        &self,
        browser: &BrowserReport,
        upstream: &UpstreamSnapshot,
        collector: &CollectorSnapshot,
    ) -> bool {
        let route = |name: &str| upstream.routes.get(name).copied().unwrap_or(0);
        self.probe_completed
            && browser.navigation_escape_attempted
            && browser.popup_escape_attempted
            && browser.download_escape_attempted
            && browser.external_scheme_escape_attempted
            && self.navigation_block_callbacks == 1
            && self.navigation_network_blocks == 1
            && self.popup_deny_callbacks == 1
            && self.download_cancel_callbacks == 1
            && self.external_scheme_guard_attached
            && self.external_scheme_native_attempt_queued
            && self.external_scheme_events >= 1
            && self.expected_external_scheme_events == self.external_scheme_events
            && self.external_scheme_native_events >= 1
            && self.external_scheme_cancellations == self.external_scheme_events
            && self.native_hardening_completed
            && self.devtools_disabled
            && self.browser_accelerators_disabled
            && self.default_context_menus_disabled
            && self.extension_install_attempted
            && self.extension_install_completed
            && self.extension_install_rejected_not_supported
            && self.environment_overrides_absent
            && self.registry_overrides_absent_before_creation
            && self.registry_overrides_absent_after_creation
            && self.devtools_active_port_absent
            && self.download_directory_empty
            && self.external_scheme_registration_volatile
            && self.external_scheme_handler_canary_verified
            && self.external_scheme_handler_canary_absent
            && self.external_scheme_registration_removed
            && route("/download/escape") == 1
            && collector.navigation_escape_requests == 0
            && collector.popup_escape_requests == 0
    }
}

/// Explicit pass/fail evidence for the development runtime.
///
/// Separate booleans preserve one machine-readable result per contract gate.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, Serialize)]
pub struct DevelopmentGates {
    pub system_resolver_has_no_nonloopback_answer: bool,
    pub webview_random_hostname_reached_loopback: bool,
    pub windows_listener_overlap_all_variants_pass: bool,
    pub malformed_upstream_response_heads_fail_closed: bool,
    pub malformed_upstream_response_bodies_fail_closed: bool,
    pub request_body_resource_limits_fail_closed: bool,
    pub response_resource_limits_fail_closed: bool,
    pub websocket_byte_rates_bounded: bool,
    pub browser_escape_matrix_pass: bool,
    pub crash_profile_persistence_pass: bool,
    pub webview_random_hostname_loaded: bool,
    pub native_cookie_set_and_read_back: bool,
    pub cookie_flags_exact: bool,
    pub javascript_cannot_read_proxy_cookie: bool,
    pub javascript_cannot_observe_secret_shape: bool,
    pub document_css_script_image_loaded: bool,
    pub fetch_get_and_unsafe_post_pass: bool,
    pub streaming_response_pass: bool,
    pub websocket_cookie_and_echo_pass: bool,
    pub every_upstream_request_has_one_valid_secret: bool,
    pub proxy_cookie_never_reaches_upstream: bool,
    pub forwarding_headers_never_reach_upstream: bool,
    pub child_hostname_receives_no_proxy_cookie: bool,
    pub external_redirect_receives_no_credentials: bool,
    pub process_environment_secret_free: bool,
    pub process_arguments_secret_free: bool,
    pub session_cookie_removed_on_clean_shutdown: bool,
    pub clean_profile_recreation_cookie_absent: bool,
    pub browsing_data_cleanup_queued: bool,
    pub webview_destroyed: bool,
}

impl DevelopmentGates {
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::fn_params_excessive_bools)]
    pub fn evaluate(
        resolution: &HostResolution,
        listener_overlap: &ListenerOverlapEvidence,
        malformed_upstream: &MalformedUpstreamEvidence,
        malformed_upstream_bodies: &MalformedUpstreamBodyEvidence,
        request_body_limits: &RequestBodyLimitEvidence,
        response_resource_limits: &ResponseResourceLimitEvidence,
        websocket_rate_limits: &WebSocketRateLimitEvidence,
        browser_escape: &BrowserEscapeEvidence,
        crash_profile: &CrashProfileEvidence,
        cookie: &CookieEvidence,
        browser: &BrowserReport,
        upstream: &UpstreamSnapshot,
        collector: &CollectorSnapshot,
        environment_secret_free: bool,
        arguments_secret_free: bool,
        cleanup_cookie_absent: bool,
        cleanup_browsing_data_queued: bool,
        window_destroyed: bool,
    ) -> Self {
        let route = |name: &str| upstream.routes.get(name).copied().unwrap_or(0) > 0;
        Self {
            system_resolver_has_no_nonloopback_answer: !matches!(
                resolution,
                HostResolution::NonLoopback(_)
            ),
            webview_random_hostname_reached_loopback: cookie.bootstrap_finished,
            windows_listener_overlap_all_variants_pass: listener_overlap
                .all_variants_prove_exact_proxy_ownership(),
            malformed_upstream_response_heads_fail_closed: malformed_upstream
                .all_response_heads_fail_closed(),
            malformed_upstream_response_bodies_fail_closed: malformed_upstream_bodies
                .all_response_bodies_fail_closed(),
            request_body_resource_limits_fail_closed: request_body_limits
                .all_request_body_limits_fail_closed(),
            response_resource_limits_fail_closed: response_resource_limits
                .all_response_resource_limits_fail_closed(),
            websocket_byte_rates_bounded: websocket_rate_limits
                .all_websocket_byte_rates_are_bounded(),
            browser_escape_matrix_pass: browser_escape
                .all_browser_escape_controls_hold(browser, upstream, collector),
            crash_profile_persistence_pass: crash_profile.all_forced_crash_controls_hold(),
            webview_random_hostname_loaded: cookie.bootstrap_finished
                && cookie.authenticated_root_finished
                && cookie.browser_report_received,
            native_cookie_set_and_read_back: cookie.authenticated_bootstrap_queued
                && cookie.readback_count_exactly_one
                && cookie.value_matches,
            cookie_flags_exact: cookie.http_only
                && cookie.same_site_strict
                && cookie.path_root
                && cookie.no_max_age
                && cookie.session_expiration,
            javascript_cannot_read_proxy_cookie: !browser.proxy_cookie_visible,
            javascript_cannot_observe_secret_shape: !browser.secret_shape_visible,
            document_css_script_image_loaded: browser.css_loaded
                && browser.script_loaded
                && browser.image_loaded
                && route("/")
                && route("/assets/site.css")
                && route("/assets/app.js")
                && route("/assets/pixel.svg"),
            fetch_get_and_unsafe_post_pass: browser.fetch_get
                && browser.fetch_post
                && route("/api/data")
                && route("/api/submit"),
            streaming_response_pass: browser.stream_read && route("/api/stream"),
            websocket_cookie_and_echo_pass: browser.websocket_echo && route("/ws"),
            every_upstream_request_has_one_valid_secret: upstream.requests > 0
                && upstream.protected_header_valid == upstream.requests
                && upstream.protected_header_invalid_count == 0,
            proxy_cookie_never_reaches_upstream: upstream.proxy_cookie_leaks == 0,
            forwarding_headers_never_reach_upstream: upstream.forwarding_header_leaks == 0
                && upstream.websocket_extension_leaks == 0
                && upstream.bootstrap_header_leaks == 0,
            child_hostname_receives_no_proxy_cookie: browser.child_host_request_completed
                && collector.child_host_requests > 0
                && collector.proxy_cookie_leaks == 0,
            external_redirect_receives_no_credentials: browser.external_redirect_completed
                && collector.external_redirect_requests > 0
                && collector.proxy_cookie_leaks == 0
                && collector.protected_header_leaks == 0
                && collector.bootstrap_header_leaks == 0,
            process_environment_secret_free: environment_secret_free,
            process_arguments_secret_free: arguments_secret_free,
            session_cookie_removed_on_clean_shutdown: cleanup_cookie_absent,
            clean_profile_recreation_cookie_absent: cookie.clean_recreation_cookie_absent,
            browsing_data_cleanup_queued: cleanup_browsing_data_queued,
            webview_destroyed: window_destroyed,
        }
    }

    fn all_pass(&self) -> bool {
        [
            self.system_resolver_has_no_nonloopback_answer,
            self.webview_random_hostname_reached_loopback,
            self.windows_listener_overlap_all_variants_pass,
            self.malformed_upstream_response_heads_fail_closed,
            self.malformed_upstream_response_bodies_fail_closed,
            self.request_body_resource_limits_fail_closed,
            self.response_resource_limits_fail_closed,
            self.websocket_byte_rates_bounded,
            self.browser_escape_matrix_pass,
            self.crash_profile_persistence_pass,
            self.webview_random_hostname_loaded,
            self.native_cookie_set_and_read_back,
            self.cookie_flags_exact,
            self.javascript_cannot_read_proxy_cookie,
            self.javascript_cannot_observe_secret_shape,
            self.document_css_script_image_loaded,
            self.fetch_get_and_unsafe_post_pass,
            self.streaming_response_pass,
            self.websocket_cookie_and_echo_pass,
            self.every_upstream_request_has_one_valid_secret,
            self.proxy_cookie_never_reaches_upstream,
            self.forwarding_headers_never_reach_upstream,
            self.child_hostname_receives_no_proxy_cookie,
            self.external_redirect_receives_no_credentials,
            self.process_environment_secret_free,
            self.process_arguments_secret_free,
            self.session_cookie_removed_on_clean_shutdown,
            self.clean_profile_recreation_cookie_absent,
            self.browsing_data_cleanup_queued,
            self.webview_destroyed,
        ]
        .into_iter()
        .all(|gate| gate)
    }
}

/// Complete secret-free report.
#[derive(Clone, Debug, Serialize)]
pub struct AcceptanceReport {
    pub transport_contract_version: u32,
    pub harness_version: &'static str,
    pub platform: &'static str,
    pub webview2_runtime: Option<String>,
    pub hostname_resolution: ResolutionReport,
    pub listener_overlap: ListenerOverlapEvidence,
    pub malformed_upstream_response_heads: MalformedUpstreamEvidence,
    pub malformed_upstream_response_bodies: MalformedUpstreamBodyEvidence,
    pub request_body_limits: RequestBodyLimitEvidence,
    pub response_resource_limits: ResponseResourceLimitEvidence,
    pub websocket_rate_limits: WebSocketRateLimitEvidence,
    pub browser_escape: BrowserEscapeEvidence,
    pub crash_profile: CrashProfileEvidence,
    pub cookie: CookieEvidence,
    pub browser: BrowserReport,
    pub upstream: UpstreamSnapshot,
    pub external_collector: CollectorSnapshot,
    pub gates: DevelopmentGates,
    pub development_gates_passed: bool,
    pub phase1_release_ready: bool,
    pub unproven_release_gates: BTreeMap<&'static str, &'static str>,
}

impl AcceptanceReport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        webview2_runtime: Option<String>,
        resolution: HostResolution,
        listener_overlap: ListenerOverlapEvidence,
        malformed_upstream_response_heads: MalformedUpstreamEvidence,
        malformed_upstream_response_bodies: MalformedUpstreamBodyEvidence,
        request_body_limits: RequestBodyLimitEvidence,
        response_resource_limits: ResponseResourceLimitEvidence,
        websocket_rate_limits: WebSocketRateLimitEvidence,
        browser_escape: BrowserEscapeEvidence,
        crash_profile: CrashProfileEvidence,
        cookie: CookieEvidence,
        browser: BrowserReport,
        upstream: UpstreamSnapshot,
        external_collector: CollectorSnapshot,
        gates: DevelopmentGates,
    ) -> Self {
        let development_gates_passed = gates.all_pass();
        let mut unproven_release_gates = BTreeMap::from([(
            "fixed_minimum_webview2",
            "the complete matrix has not run against a reviewed fixed minimum runtime",
        )]);
        if !crash_profile.all_forced_crash_controls_hold() {
            unproven_release_gates.insert(
                "crash_profile_persistence",
                "a cross-process forced termination has not proven cookie presence before the crash, absence after same-profile recreation, bypass of graceful cleanup, and profile removal",
            );
        }
        if !gates.browser_escape_matrix_pass {
            unproven_release_gates.insert(
                "browser_escape_matrix",
                "navigation, popup, download, external-scheme, devtools, extension, and remote-debugging controls have not all passed active real-WebView2 probes",
            );
        }
        if !websocket_rate_limits.all_websocket_byte_rates_are_bounded() {
            unproven_release_gates.insert(
                "resource_and_timeout_matrix",
                "WebSocket byte-rate shaping has not proven independent client-to-upstream and upstream-to-client bounds with backpressure",
            );
        }
        if !listener_overlap.all_variants_prove_exact_proxy_ownership() {
            unproven_release_gates.insert(
                "listener_overlap_matrix",
                "IPv4 wildcard, IPv6 v6-only wildcard, and IPv6 dual-stack wildcard traffic to both exact listeners have not all proven exact-proxy ownership with zero wildcard accepts",
            );
        }
        if !malformed_upstream_response_bodies.all_response_bodies_fail_closed() {
            unproven_release_gates.insert(
                "malformed_upstream_body_matrix",
                "valid fragmented body baselines plus truncated fixed-length, malformed chunked, unsafe trailer, limit, and response-splitting cases have not all proven bounded fail-closed behavior",
            );
        }
        Self {
            transport_contract_version: 2,
            harness_version: env!("CARGO_PKG_VERSION"),
            platform: std::env::consts::OS,
            webview2_runtime,
            hostname_resolution: ResolutionReport::from(resolution),
            listener_overlap,
            malformed_upstream_response_heads,
            malformed_upstream_response_bodies,
            request_body_limits,
            response_resource_limits,
            websocket_rate_limits,
            browser_escape,
            crash_profile,
            cookie,
            browser,
            upstream,
            external_collector,
            gates,
            development_gates_passed,
            phase1_release_ready: false,
            unproven_release_gates,
        }
    }

    pub fn write(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|_| io::Error::other("report encoding failed"))?;
        fs::write(path, bytes)
    }
}

/// Secret-free resolver evidence.
#[derive(Clone, Debug, Serialize)]
pub struct ResolutionReport {
    pub status: &'static str,
    pub address_count: usize,
    pub ipv4_loopback: bool,
    pub ipv6_loopback: bool,
}

impl From<HostResolution> for ResolutionReport {
    fn from(resolution: HostResolution) -> Self {
        match resolution {
            HostResolution::Loopback(addresses) => Self {
                status: "loopback-only",
                address_count: addresses.len(),
                ipv4_loopback: addresses.iter().any(std::net::IpAddr::is_ipv4),
                ipv6_loopback: addresses.iter().any(std::net::IpAddr::is_ipv6),
            },
            HostResolution::NonLoopback(addresses) => Self {
                status: "non-loopback-answer",
                address_count: addresses.len(),
                ipv4_loopback: false,
                ipv6_loopback: false,
            },
            HostResolution::Unavailable => Self {
                status: "unavailable",
                address_count: 0,
                ipv4_loopback: false,
                ipv6_loopback: false,
            },
        }
    }
}

pub fn write_failure_report(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        path,
        b"{\n  \"transport_contract_version\": 2,\n  \"development_gates_passed\": false,\n  \"phase1_release_ready\": false,\n  \"failure\": \"harness failed before producing acceptance evidence\"\n}\n",
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rpackit_transport_testkit::{
        ListenerDualStackOverlapEvidence, ListenerFamilyOverlapEvidence,
    };

    use super::*;

    fn report(listener_overlap: ListenerOverlapEvidence) -> AcceptanceReport {
        report_with_evidence(
            listener_overlap,
            MalformedUpstreamEvidence::default(),
            MalformedUpstreamBodyEvidence::default(),
        )
    }

    fn report_with_malformed(
        listener_overlap: ListenerOverlapEvidence,
        malformed_upstream: MalformedUpstreamEvidence,
    ) -> AcceptanceReport {
        report_with_evidence(
            listener_overlap,
            malformed_upstream,
            MalformedUpstreamBodyEvidence::default(),
        )
    }

    fn report_with_evidence(
        listener_overlap: ListenerOverlapEvidence,
        malformed_upstream: MalformedUpstreamEvidence,
        malformed_upstream_bodies: MalformedUpstreamBodyEvidence,
    ) -> AcceptanceReport {
        AcceptanceReport::new(
            None,
            HostResolution::Unavailable,
            listener_overlap,
            malformed_upstream,
            malformed_upstream_bodies,
            RequestBodyLimitEvidence::default(),
            ResponseResourceLimitEvidence::default(),
            WebSocketRateLimitEvidence::default(),
            BrowserEscapeEvidence::default(),
            CrashProfileEvidence::default(),
            CookieEvidence::default(),
            BrowserReport::default(),
            UpstreamSnapshot::default(),
            CollectorSnapshot::default(),
            DevelopmentGates::default(),
        )
    }

    fn passing_family() -> ListenerFamilyOverlapEvidence {
        ListenerFamilyOverlapEvidence {
            wildcard_bind_succeeded: true,
            requests_attempted: 8,
            proxy_unauthorized_responses: 8,
            wildcard_accepts: 0,
            probe_completed: true,
            exact_proxy_won: true,
        }
    }

    fn passing_dual_stack() -> ListenerDualStackOverlapEvidence {
        ListenerDualStackOverlapEvidence {
            wildcard_bind_succeeded: true,
            ipv4_requests_attempted: 8,
            ipv4_proxy_unauthorized_responses: 8,
            ipv6_requests_attempted: 8,
            ipv6_proxy_unauthorized_responses: 8,
            wildcard_accepts: 0,
            probe_completed: true,
            exact_proxies_won: true,
        }
    }

    #[test]
    fn listener_overlap_gap_is_removed_only_after_every_variant_passes() {
        let unproven = report(ListenerOverlapEvidence::default());
        assert!(
            unproven
                .unproven_release_gates
                .contains_key("listener_overlap_matrix")
        );

        let missing_dual_stack = report(ListenerOverlapEvidence {
            windows_probe_completed: true,
            ipv4_wildcard: passing_family(),
            ipv6_v6_only_wildcard: passing_family(),
            ipv6_dual_stack_wildcard: ListenerDualStackOverlapEvidence::default(),
        });
        assert!(
            missing_dual_stack
                .unproven_release_gates
                .contains_key("listener_overlap_matrix")
        );

        let proven = report(ListenerOverlapEvidence {
            windows_probe_completed: true,
            ipv4_wildcard: passing_family(),
            ipv6_v6_only_wildcard: passing_family(),
            ipv6_dual_stack_wildcard: passing_dual_stack(),
        });
        assert!(
            !proven
                .unproven_release_gates
                .contains_key("listener_overlap_matrix")
        );
        assert!(!proven.phase1_release_ready);
    }

    #[test]
    fn malformed_response_counts_are_reported_without_claiming_release_readiness() {
        let cases = [
            "conflicting_content_length",
            "content_length_and_transfer_encoding",
            "unsupported_transfer_encoding",
            "chunked_not_final",
            "obsolete_header_folding",
            "whitespace_before_colon",
            "invalid_header_name",
            "bare_line_feeds",
            "invalid_status_code",
            "oversized_response_head",
            "too_many_headers",
            "duplicate_connection",
            "protected_connection_nomination",
            "ambiguous_location",
            "reserved_proxy_cookie",
            "unsolicited_protocol_switch",
            "websocket_bare_line_feeds",
            "websocket_conflicting_content_length",
            "websocket_oversized_response_head",
            "websocket_too_many_headers",
            "websocket_content_length",
            "websocket_transfer_encoding",
            "websocket_duplicate_connection",
            "websocket_duplicate_upgrade",
            "websocket_wrong_upgrade",
            "websocket_missing_accept",
            "websocket_wrong_accept",
            "websocket_duplicate_accept",
            "websocket_unoffered_protocol",
            "websocket_duplicate_protocol",
            "websocket_unsolicited_extensions",
            "websocket_protected_connection_nomination",
        ]
        .into_iter()
        .map(|name| (name.to_owned(), true))
        .collect::<BTreeMap<_, _>>();
        let evidence = MalformedUpstreamEvidence {
            valid_baseline_passed: true,
            valid_websocket_baseline_passed: true,
            http_cases_attempted: 16,
            http_fail_closed_responses: 16,
            websocket_cases_attempted: 16,
            websocket_fail_closed_responses: 16,
            cases_attempted: 32,
            fail_closed_responses: 32,
            upstream_requests_with_valid_secret: 34,
            upstream_websocket_requests_valid: 17,
            unexpected_downstream_upgrades: 0,
            attacker_markers_forwarded: 0,
            cases,
            probe_completed: true,
        };
        assert!(evidence.all_response_heads_fail_closed());

        let gates = DevelopmentGates::evaluate(
            &HostResolution::Unavailable,
            &ListenerOverlapEvidence::default(),
            &evidence,
            &MalformedUpstreamBodyEvidence::default(),
            &RequestBodyLimitEvidence::default(),
            &ResponseResourceLimitEvidence::default(),
            &WebSocketRateLimitEvidence::default(),
            &BrowserEscapeEvidence::default(),
            &CrashProfileEvidence::default(),
            &CookieEvidence::default(),
            &BrowserReport::default(),
            &UpstreamSnapshot::default(),
            &CollectorSnapshot::default(),
            true,
            true,
            false,
            false,
            false,
        );
        assert!(gates.malformed_upstream_response_heads_fail_closed);

        let report = report_with_malformed(ListenerOverlapEvidence::default(), evidence);
        let serialized = serde_json::to_string(&report).unwrap_or_default();
        assert!(serialized.contains("\"http_cases_attempted\":16"));
        assert!(serialized.contains("\"websocket_cases_attempted\":16"));
        assert!(serialized.contains("\"cases_attempted\":32"));
        assert!(serialized.contains("\"fail_closed_responses\":32"));
        assert!(serialized.contains("\"upstream_requests_with_valid_secret\":34"));
        assert!(serialized.contains("\"upstream_websocket_requests_valid\":17"));
        assert!(serialized.contains("\"unexpected_downstream_upgrades\":0"));
        assert!(!serialized.contains("rp-"));
        assert!(
            report
                .unproven_release_gates
                .contains_key("malformed_upstream_body_matrix")
        );
        assert!(!report.phase1_release_ready);
    }

    #[test]
    fn malformed_body_gate_is_removed_only_after_every_named_case_passes() {
        let cases = [
            "declared_length_over_limit",
            "declared_trailer",
            "no_content_content_length",
            "no_content_transfer_encoding",
            "reset_content_nonzero_length",
            "reset_content_transfer_encoding",
            "truncated_content_length_empty",
            "truncated_content_length_partial",
            "invalid_chunk_size",
            "overflowing_chunk_size",
            "truncated_chunk_data",
            "missing_chunk_data_crlf",
            "missing_terminal_chunk",
            "malformed_trailer",
            "protected_trailer",
            "oversized_trailer",
            "too_many_trailers",
            "chunked_body_over_limit",
            "close_delimited_body_over_limit",
            "no_content_malicious_body",
            "reset_content_close_delimited_body",
            "bytes_after_terminal_chunk",
            "bytes_after_content_length",
        ]
        .into_iter()
        .map(|name| (name.to_owned(), true))
        .collect::<BTreeMap<_, _>>();
        let evidence = MalformedUpstreamBodyEvidence {
            valid_content_length_baseline_passed: true,
            valid_chunked_baseline_passed: true,
            valid_close_delimited_baseline_passed: true,
            valid_head_nonzero_length_baseline_passed: true,
            valid_not_modified_nonzero_length_baseline_passed: true,
            valid_no_content_baseline_passed: true,
            valid_reset_content_zero_length_baseline_passed: true,
            cases_attempted: 23,
            exact_bad_gateway_responses: 6,
            stream_fail_closed_terminations: 12,
            close_delimited_limit_terminations: 1,
            bodyless_status_terminations: 2,
            isolated_complete_responses: 2,
            bounded_terminations: 23,
            upstream_requests_with_valid_secret: 30,
            second_downstream_requests_attempted: 30,
            downstream_connections_physically_closed: 30,
            second_downstream_responses: 0,
            attacker_markers_forwarded: 0,
            reusable_downstream_responses: 0,
            cases,
            probe_completed: true,
        };
        assert!(evidence.all_response_bodies_fail_closed());

        let gates = DevelopmentGates::evaluate(
            &HostResolution::Unavailable,
            &ListenerOverlapEvidence::default(),
            &MalformedUpstreamEvidence::default(),
            &evidence,
            &RequestBodyLimitEvidence::default(),
            &ResponseResourceLimitEvidence::default(),
            &WebSocketRateLimitEvidence::default(),
            &BrowserEscapeEvidence::default(),
            &CrashProfileEvidence::default(),
            &CookieEvidence::default(),
            &BrowserReport::default(),
            &UpstreamSnapshot::default(),
            &CollectorSnapshot::default(),
            true,
            true,
            false,
            false,
            false,
        );
        assert!(gates.malformed_upstream_response_bodies_fail_closed);

        let report = report_with_evidence(
            ListenerOverlapEvidence::default(),
            MalformedUpstreamEvidence::default(),
            evidence,
        );
        let serialized = serde_json::to_string(&report).unwrap_or_default();
        assert!(serialized.contains("\"cases_attempted\":23"));
        assert!(serialized.contains("\"exact_bad_gateway_responses\":6"));
        assert!(serialized.contains("\"stream_fail_closed_terminations\":12"));
        assert!(serialized.contains("\"close_delimited_limit_terminations\":1"));
        assert!(serialized.contains("\"bodyless_status_terminations\":2"));
        assert!(serialized.contains("\"isolated_complete_responses\":2"));
        assert!(serialized.contains("\"bounded_terminations\":23"));
        assert!(serialized.contains("\"upstream_requests_with_valid_secret\":30"));
        assert!(serialized.contains("\"second_downstream_requests_attempted\":30"));
        assert!(serialized.contains("\"downstream_connections_physically_closed\":30"));
        assert!(serialized.contains("\"second_downstream_responses\":0"));
        assert!(serialized.contains("\"attacker_markers_forwarded\":0"));
        assert!(serialized.contains("\"reusable_downstream_responses\":0"));
        assert!(!serialized.contains("rpackit-malformed-upstream-marker"));
        assert!(
            !report
                .unproven_release_gates
                .contains_key("malformed_upstream_body_matrix")
        );
        assert!(!report.phase1_release_ready);
    }

    #[test]
    fn request_body_limit_evidence_is_serialized_without_claiming_readiness() {
        let evidence = RequestBodyLimitEvidence {
            valid_baseline_passed: true,
            byte_limit_passed: true,
            idle_limit_passed: true,
            minimum_rate_limit_passed: true,
            total_timeout_limit_passed: true,
            trailer_limit_passed: true,
            cases_attempted: 5,
            bounded_terminations: 5,
            upstream_body_probe_requests: 4,
            upstream_requests_with_valid_secret: 4,
            upstream_requests_with_invalid_secret: 0,
            proxy_cookie_leaks: 0,
            bootstrap_header_leaks: 0,
            probe_completed: true,
        };
        assert!(evidence.all_request_body_limits_fail_closed());

        let gates = DevelopmentGates::evaluate(
            &HostResolution::Unavailable,
            &ListenerOverlapEvidence::default(),
            &MalformedUpstreamEvidence::default(),
            &MalformedUpstreamBodyEvidence::default(),
            &evidence,
            &ResponseResourceLimitEvidence::default(),
            &WebSocketRateLimitEvidence::default(),
            &BrowserEscapeEvidence::default(),
            &CrashProfileEvidence::default(),
            &CookieEvidence::default(),
            &BrowserReport::default(),
            &UpstreamSnapshot::default(),
            &CollectorSnapshot::default(),
            true,
            true,
            false,
            false,
            false,
        );
        assert!(gates.request_body_resource_limits_fail_closed);

        let report = AcceptanceReport::new(
            None,
            HostResolution::Unavailable,
            ListenerOverlapEvidence::default(),
            MalformedUpstreamEvidence::default(),
            MalformedUpstreamBodyEvidence::default(),
            evidence,
            ResponseResourceLimitEvidence::default(),
            WebSocketRateLimitEvidence::default(),
            BrowserEscapeEvidence::default(),
            CrashProfileEvidence::default(),
            CookieEvidence::default(),
            BrowserReport::default(),
            UpstreamSnapshot::default(),
            CollectorSnapshot::default(),
            gates,
        );
        let serialized = serde_json::to_string(&report).unwrap_or_default();
        assert!(serialized.contains("\"valid_baseline_passed\":true"));
        assert!(serialized.contains("\"byte_limit_passed\":true"));
        assert!(serialized.contains("\"minimum_rate_limit_passed\":true"));
        assert!(serialized.contains("\"trailer_limit_passed\":true"));
        assert!(serialized.contains("\"upstream_requests_with_valid_secret\":4"));
        assert!(
            report
                .unproven_release_gates
                .contains_key("resource_and_timeout_matrix")
        );
        assert!(!report.phase1_release_ready);
    }

    #[test]
    fn response_resource_evidence_is_serialized_without_claiming_readiness() {
        let evidence = ResponseResourceLimitEvidence {
            valid_identity_baseline_passed: true,
            valid_gzip_baseline_passed: true,
            decoded_representation_metadata_stripped: true,
            idle_limit_passed: true,
            minimum_rate_limit_passed: true,
            decompressed_size_limit_passed: true,
            malformed_encoding_passed: true,
            unsupported_encoding_passed: true,
            compressed_expansion_encoded_bytes: 67,
            compressed_expansion_decoded_bytes: 4128,
            decompressed_bytes_forwarded: 0,
            cases_attempted: 5,
            bounded_terminations: 5,
            upstream_requests_with_valid_secret: 7,
            upstream_requests_with_invalid_secret: 0,
            proxy_cookie_leaks: 0,
            bootstrap_header_leaks: 0,
            attacker_markers_forwarded: 0,
            probe_completed: true,
        };
        assert!(evidence.all_response_resource_limits_fail_closed());

        let gates = DevelopmentGates::evaluate(
            &HostResolution::Unavailable,
            &ListenerOverlapEvidence::default(),
            &MalformedUpstreamEvidence::default(),
            &MalformedUpstreamBodyEvidence::default(),
            &RequestBodyLimitEvidence::default(),
            &evidence,
            &WebSocketRateLimitEvidence::default(),
            &BrowserEscapeEvidence::default(),
            &CrashProfileEvidence::default(),
            &CookieEvidence::default(),
            &BrowserReport::default(),
            &UpstreamSnapshot::default(),
            &CollectorSnapshot::default(),
            true,
            true,
            false,
            false,
            false,
        );
        assert!(gates.response_resource_limits_fail_closed);

        let report = AcceptanceReport::new(
            None,
            HostResolution::Unavailable,
            ListenerOverlapEvidence::default(),
            MalformedUpstreamEvidence::default(),
            MalformedUpstreamBodyEvidence::default(),
            RequestBodyLimitEvidence::default(),
            evidence,
            WebSocketRateLimitEvidence::default(),
            BrowserEscapeEvidence::default(),
            CrashProfileEvidence::default(),
            CookieEvidence::default(),
            BrowserReport::default(),
            UpstreamSnapshot::default(),
            CollectorSnapshot::default(),
            gates,
        );
        let serialized = serde_json::to_string(&report).unwrap_or_default();
        assert!(serialized.contains("\"valid_gzip_baseline_passed\":true"));
        assert!(serialized.contains("\"decompressed_size_limit_passed\":true"));
        assert!(serialized.contains("\"compressed_expansion_encoded_bytes\":67"));
        assert!(serialized.contains("\"compressed_expansion_decoded_bytes\":4128"));
        assert!(serialized.contains("\"upstream_requests_with_valid_secret\":7"));
        assert!(!serialized.contains("rpackit-response-resource-marker"));
        assert!(
            report
                .unproven_release_gates
                .contains_key("resource_and_timeout_matrix")
        );
        assert!(!report.phase1_release_ready);
    }

    #[test]
    fn websocket_rate_evidence_closes_the_remaining_resource_gap() {
        let evidence = WebSocketRateLimitEvidence {
            valid_small_baseline_passed: true,
            client_to_upstream_rate_bounded: true,
            upstream_to_client_rate_bounded: true,
            payload_bytes: 100,
            max_bytes_per_second: 100,
            burst_window_millis: 100,
            client_to_upstream_elapsed_millis: 900,
            upstream_to_client_elapsed_millis: 900,
            rate_cases_attempted: 2,
            bounded_completions: 2,
            upstream_requests_with_valid_secret: 3,
            upstream_requests_with_invalid_secret: 0,
            normalized_upstream_websocket_requests: 3,
            proxy_cookie_leaks: 0,
            bootstrap_header_leaks: 0,
            probe_completed: true,
        };
        assert!(evidence.all_websocket_byte_rates_are_bounded());

        let gates = DevelopmentGates::evaluate(
            &HostResolution::Unavailable,
            &ListenerOverlapEvidence::default(),
            &MalformedUpstreamEvidence::default(),
            &MalformedUpstreamBodyEvidence::default(),
            &RequestBodyLimitEvidence::default(),
            &ResponseResourceLimitEvidence::default(),
            &evidence,
            &BrowserEscapeEvidence::default(),
            &CrashProfileEvidence::default(),
            &CookieEvidence::default(),
            &BrowserReport::default(),
            &UpstreamSnapshot::default(),
            &CollectorSnapshot::default(),
            true,
            true,
            false,
            false,
            false,
        );
        assert!(gates.websocket_byte_rates_bounded);

        let report = AcceptanceReport::new(
            None,
            HostResolution::Unavailable,
            ListenerOverlapEvidence::default(),
            MalformedUpstreamEvidence::default(),
            MalformedUpstreamBodyEvidence::default(),
            RequestBodyLimitEvidence::default(),
            ResponseResourceLimitEvidence::default(),
            evidence,
            BrowserEscapeEvidence::default(),
            CrashProfileEvidence::default(),
            CookieEvidence::default(),
            BrowserReport::default(),
            UpstreamSnapshot::default(),
            CollectorSnapshot::default(),
            gates,
        );
        let serialized = serde_json::to_string(&report).unwrap_or_default();
        assert!(serialized.contains("\"client_to_upstream_rate_bounded\":true"));
        assert!(serialized.contains("\"upstream_to_client_rate_bounded\":true"));
        assert!(serialized.contains("\"max_bytes_per_second\":100"));
        assert!(serialized.contains("\"normalized_upstream_websocket_requests\":3"));
        assert!(
            !report
                .unproven_release_gates
                .contains_key("resource_and_timeout_matrix")
        );
        assert!(!report.phase1_release_ready);
    }

    fn passing_crash_profile_evidence() -> CrashProfileEvidence {
        CrashProfileEvidence {
            probe_completed: true,
            producer_paths_scoped_to_system_temp: true,
            producer_spawned: true,
            producer_received_no_secret_input: true,
            producer_cookie_verified_before_crash: true,
            producer_profile_populated_before_crash: true,
            producer_forcibly_terminated: true,
            producer_reaped_after_termination: true,
            graceful_cleanup_sentinel_absent: true,
            control_marker_secret_free: true,
            crashed_profile_recreation_completed: true,
            crashed_profile_cookie_absent: true,
            recreation_webview_destroyed: true,
            crash_profile_directory_removed: true,
        }
    }

    #[test]
    fn crash_profile_gap_closes_only_with_forced_cross_process_evidence() {
        let evidence = passing_crash_profile_evidence();
        assert!(evidence.all_forced_crash_controls_hold());
        let gates = DevelopmentGates::evaluate(
            &HostResolution::Unavailable,
            &ListenerOverlapEvidence::default(),
            &MalformedUpstreamEvidence::default(),
            &MalformedUpstreamBodyEvidence::default(),
            &RequestBodyLimitEvidence::default(),
            &ResponseResourceLimitEvidence::default(),
            &WebSocketRateLimitEvidence::default(),
            &BrowserEscapeEvidence::default(),
            &evidence,
            &CookieEvidence::default(),
            &BrowserReport::default(),
            &UpstreamSnapshot::default(),
            &CollectorSnapshot::default(),
            true,
            true,
            false,
            false,
            false,
        );
        assert!(gates.crash_profile_persistence_pass);

        let report = AcceptanceReport::new(
            None,
            HostResolution::Unavailable,
            ListenerOverlapEvidence::default(),
            MalformedUpstreamEvidence::default(),
            MalformedUpstreamBodyEvidence::default(),
            RequestBodyLimitEvidence::default(),
            ResponseResourceLimitEvidence::default(),
            WebSocketRateLimitEvidence::default(),
            BrowserEscapeEvidence::default(),
            evidence.clone(),
            CookieEvidence::default(),
            BrowserReport::default(),
            UpstreamSnapshot::default(),
            CollectorSnapshot::default(),
            gates,
        );
        assert!(
            !report
                .unproven_release_gates
                .contains_key("crash_profile_persistence")
        );
        let serialized = serde_json::to_string(&report).unwrap_or_default();
        assert!(serialized.contains("\"producer_forcibly_terminated\":true"));
        assert!(serialized.contains("\"crashed_profile_cookie_absent\":true"));
        assert!(!serialized.contains("rp-"));

        let mut incomplete = evidence;
        incomplete.graceful_cleanup_sentinel_absent = false;
        assert!(!incomplete.all_forced_crash_controls_hold());
        assert!(!report.phase1_release_ready);
    }

    fn passing_browser_escape_evidence() -> BrowserEscapeEvidence {
        BrowserEscapeEvidence {
            probe_completed: true,
            navigation_block_callbacks: 1,
            navigation_network_blocks: 1,
            popup_deny_callbacks: 1,
            download_cancel_callbacks: 1,
            external_scheme_guard_attached: true,
            external_scheme_native_attempt_queued: true,
            external_scheme_events: 1,
            expected_external_scheme_events: 1,
            external_scheme_native_events: 1,
            external_scheme_cancellations: 1,
            native_hardening_completed: true,
            devtools_disabled: true,
            browser_accelerators_disabled: true,
            default_context_menus_disabled: true,
            extension_install_attempted: true,
            extension_install_completed: true,
            extension_install_rejected_not_supported: true,
            environment_overrides_absent: true,
            registry_overrides_absent_before_creation: true,
            registry_overrides_absent_after_creation: true,
            devtools_active_port_absent: true,
            download_directory_empty: true,
            external_scheme_registration_volatile: true,
            external_scheme_handler_canary_verified: true,
            external_scheme_handler_canary_absent: true,
            external_scheme_registration_removed: true,
        }
    }

    #[test]
    fn browser_escape_gap_closes_only_with_active_fail_closed_evidence() {
        let evidence = passing_browser_escape_evidence();
        let browser = BrowserReport {
            navigation_escape_attempted: true,
            popup_escape_attempted: true,
            download_escape_attempted: true,
            external_scheme_escape_attempted: true,
            ..BrowserReport::default()
        };
        let upstream = UpstreamSnapshot {
            routes: BTreeMap::from([("/download/escape".to_owned(), 1)]),
            ..UpstreamSnapshot::default()
        };
        let collector = CollectorSnapshot::default();
        assert!(evidence.all_browser_escape_controls_hold(&browser, &upstream, &collector));

        let gates = DevelopmentGates::evaluate(
            &HostResolution::Unavailable,
            &ListenerOverlapEvidence::default(),
            &MalformedUpstreamEvidence::default(),
            &MalformedUpstreamBodyEvidence::default(),
            &RequestBodyLimitEvidence::default(),
            &ResponseResourceLimitEvidence::default(),
            &WebSocketRateLimitEvidence::default(),
            &evidence,
            &CrashProfileEvidence::default(),
            &CookieEvidence::default(),
            &browser,
            &upstream,
            &collector,
            true,
            true,
            false,
            false,
            false,
        );
        assert!(gates.browser_escape_matrix_pass);

        let report = AcceptanceReport::new(
            None,
            HostResolution::Unavailable,
            ListenerOverlapEvidence::default(),
            MalformedUpstreamEvidence::default(),
            MalformedUpstreamBodyEvidence::default(),
            RequestBodyLimitEvidence::default(),
            ResponseResourceLimitEvidence::default(),
            WebSocketRateLimitEvidence::default(),
            evidence.clone(),
            CrashProfileEvidence::default(),
            CookieEvidence::default(),
            browser,
            upstream,
            collector,
            gates,
        );
        assert!(
            !report
                .unproven_release_gates
                .contains_key("browser_escape_matrix")
        );
        assert!(!report.phase1_release_ready);

        let leaked = CollectorSnapshot {
            navigation_escape_requests: 1,
            ..CollectorSnapshot::default()
        };
        assert!(!evidence.all_browser_escape_controls_hold(
            &BrowserReport {
                navigation_escape_attempted: true,
                popup_escape_attempted: true,
                download_escape_attempted: true,
                external_scheme_escape_attempted: true,
                ..BrowserReport::default()
            },
            &UpstreamSnapshot {
                routes: BTreeMap::from([("/download/escape".to_owned(), 1)]),
                ..UpstreamSnapshot::default()
            },
            &leaked,
        ));
    }
}
