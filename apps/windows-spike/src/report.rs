//! Secret-free acceptance report schema.

use std::{collections::BTreeMap, fs, io, path::Path};

use rpackit_transport::HostResolution;
use rpackit_transport_testkit::{
    BrowserReport, CollectorSnapshot, ListenerOverlapEvidence, UpstreamSnapshot,
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

/// Explicit pass/fail evidence for the development runtime.
///
/// Separate booleans preserve one machine-readable result per contract gate.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, Serialize)]
pub struct DevelopmentGates {
    pub system_resolver_has_no_nonloopback_answer: bool,
    pub webview_random_hostname_reached_loopback: bool,
    pub windows_listener_overlap_all_variants_pass: bool,
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
        cookie: CookieEvidence,
        browser: BrowserReport,
        upstream: UpstreamSnapshot,
        external_collector: CollectorSnapshot,
        gates: DevelopmentGates,
    ) -> Self {
        let development_gates_passed = gates.all_pass();
        let mut unproven_release_gates = BTreeMap::from([
            (
                "fixed_minimum_webview2",
                "the complete matrix has not run against a reviewed fixed minimum runtime",
            ),
            (
                "crash_profile_persistence",
                "forced-crash profile recreation is not implemented in this harness revision",
            ),
            (
                "browser_escape_matrix",
                "configured navigation, popup, download, custom-scheme, devtools, extension, and remote-debugging controls are not all exercised end to end",
            ),
            (
                "resource_and_timeout_matrix",
                "HTTP idle/body-rate and WebSocket byte-rate abuse gates are not yet complete; WebSocket activity-idle shutdown is tested",
            ),
            (
                "negative_transport_matrix",
                "the complete malformed upstream framing and browser escape matrix has not yet run across every supported runtime",
            ),
        ]);
        if !listener_overlap.all_variants_prove_exact_proxy_ownership() {
            unproven_release_gates.insert(
                "listener_overlap_matrix",
                "IPv4 wildcard, IPv6 v6-only wildcard, and IPv6 dual-stack wildcard traffic to both exact listeners have not all proven exact-proxy ownership with zero wildcard accepts",
            );
        }
        Self {
            transport_contract_version: 2,
            harness_version: env!("CARGO_PKG_VERSION"),
            platform: std::env::consts::OS,
            webview2_runtime,
            hostname_resolution: ResolutionReport::from(resolution),
            listener_overlap,
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
    use rpackit_transport_testkit::{
        ListenerDualStackOverlapEvidence, ListenerFamilyOverlapEvidence,
    };

    use super::*;

    fn report(listener_overlap: ListenerOverlapEvidence) -> AcceptanceReport {
        AcceptanceReport::new(
            None,
            HostResolution::Unavailable,
            listener_overlap,
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
}
