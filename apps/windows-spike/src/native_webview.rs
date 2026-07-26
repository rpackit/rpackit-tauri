//! Narrow audited `WebView2` bootstrap and browser-escape boundary.
//!
//! Tauri does not currently expose initial-navigation headers. The one unsafe
//! block below calls the pinned `WebView2` COM API to create exactly one GET
//! request carrying the one-time bootstrap credential. A separate
//! credential-free document filter replaces external HTTP(S) navigations
//! before network access. No general credential injection or JavaScript bridge
//! is installed.

#![allow(unsafe_code)]

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use crate::report::BrowserEscapeProbe;
use rpackit_transport::{BOOTSTRAP_HEADER_NAME, Secret};
use tauri::{WebviewWindow, Wry};
use url::Url;
use webview2_com::{
    LaunchingExternalUriSchemeEventHandler,
    Microsoft::Web::WebView2::Win32::{
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT, COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT,
        ICoreWebView2_2, ICoreWebView2_13, ICoreWebView2_18, ICoreWebView2Environment2,
        ICoreWebView2Profile7, ICoreWebView2Settings3,
    },
    ProfileAddBrowserExtensionCompletedHandler, WebResourceRequestedEventHandler, take_pwstr,
};
use windows::{
    Win32::System::Com::IStream,
    core::{BOOL, HRESULT, HSTRING, Interface as _, PWSTR},
};
use zeroize::Zeroizing;

pub(crate) const EXTERNAL_SCHEME_PROBE_URI: &str = "mailto:rpackit-browser-escape@example.invalid";
const ERROR_NOT_SUPPORTED: u32 = 50;

/// Apply native settings that Tauri does not expose as one auditable builder
/// boundary, attach the external-scheme guard, and actively attempt to install
/// a valid unpacked extension while extension support is disabled.
#[allow(clippy::too_many_lines)]
pub fn install_browser_escape_guards(
    window: &WebviewWindow<Wry>,
    probe: Arc<BrowserEscapeProbe>,
    allowed_proxy_origin: Url,
    navigation_escape_url: Url,
    extension_path: PathBuf,
    download_directory: PathBuf,
) -> tauri::Result<()> {
    window.with_webview(move |platform| {
        let setup_probe = Arc::clone(&probe);
        let result = (|| -> windows::core::Result<()> {
            // SAFETY: Tauri runs `with_webview` and all registered callbacks on
            // the WebView UI thread. Interfaces are cast from this exact
            // controller, copied strings outlive each COM call, WebView2 retains
            // registered handlers, and no raw pointer escapes.
            unsafe {
                let core = platform.controller().CoreWebView2()?;
                let settings = core.Settings()?;
                settings.SetAreDevToolsEnabled(false)?;
                settings.SetAreDefaultContextMenusEnabled(false)?;
                let settings3: ICoreWebView2Settings3 = settings.cast()?;
                settings3.SetAreBrowserAcceleratorKeysEnabled(false)?;

                let mut devtools_enabled = BOOL::default();
                let mut context_menus_enabled = BOOL::default();
                let mut browser_accelerators_enabled = BOOL::default();
                settings.AreDevToolsEnabled(&raw mut devtools_enabled)?;
                settings.AreDefaultContextMenusEnabled(&raw mut context_menus_enabled)?;
                settings3
                    .AreBrowserAcceleratorKeysEnabled(&raw mut browser_accelerators_enabled)?;
                setup_probe.record_settings(
                    !devtools_enabled.as_bool(),
                    !browser_accelerators_enabled.as_bool(),
                    !context_menus_enabled.as_bool(),
                );

                let resource_environment = platform.environment().clone();
                let resource_probe = Arc::clone(&setup_probe);
                let resource_handler =
                    WebResourceRequestedEventHandler::create(Box::new(move |_, args| {
                        let Some(args) = args else {
                            return Ok(());
                        };
                        let mut context = COREWEBVIEW2_WEB_RESOURCE_CONTEXT::default();
                        args.ResourceContext(&raw mut context)?;
                        if context != COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT {
                            return Ok(());
                        }
                        let request = args.Request()?;
                        let mut uri = PWSTR::null();
                        request.Uri(&raw mut uri)?;
                        let uri = take_pwstr(uri);
                        let Ok(url) = Url::parse(&uri) else {
                            return Ok(());
                        };
                        if document_origin_is_allowed(&url, &allowed_proxy_origin)
                            || !matches!(url.scheme(), "http" | "https")
                        {
                            return Ok(());
                        }
                        let response = resource_environment.CreateWebResourceResponse(
                            None::<&IStream>,
                            403,
                            &HSTRING::from("Forbidden"),
                            &HSTRING::from(
                                "Content-Type: text/plain\r\nCache-Control: no-store\r\n",
                            ),
                        )?;
                        args.SetResponse(&response)?;
                        if url == navigation_escape_url {
                            resource_probe.record_navigation_network_block();
                        }
                        Ok(())
                    }));
                core.AddWebResourceRequestedFilter(
                    &HSTRING::from("*"),
                    COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT,
                )?;
                let mut resource_token = 0_i64;
                core.add_WebResourceRequested(&resource_handler, &raw mut resource_token)?;

                let external_probe = Arc::clone(&setup_probe);
                let external_handler =
                    LaunchingExternalUriSchemeEventHandler::create(Box::new(move |_, args| {
                        let Some(args) = args else {
                            return Ok(());
                        };
                        let mut uri = PWSTR::null();
                        args.Uri(&raw mut uri)?;
                        let uri = take_pwstr(uri);
                        args.SetCancel(true)?;
                        external_probe.record_external_scheme_event(
                            uri.eq_ignore_ascii_case(EXTERNAL_SCHEME_PROBE_URI),
                            true,
                        );
                        Ok(())
                    }));
                let core18: ICoreWebView2_18 = core.cast()?;
                let mut external_token = 0_i64;
                core18
                    .add_LaunchingExternalUriScheme(&external_handler, &raw mut external_token)?;
                setup_probe.record_external_scheme_guard_attached();

                let core13: ICoreWebView2_13 = core.cast()?;
                let profile = core13.Profile()?;
                profile
                    .SetDefaultDownloadFolderPath(&HSTRING::from(download_directory.as_path()))?;
                let profile7: ICoreWebView2Profile7 = profile.cast()?;
                let extension_probe = Arc::clone(&setup_probe);
                let extension_handler = ProfileAddBrowserExtensionCompletedHandler::create(
                    Box::new(move |error_code, extension| {
                        extension_probe.record_extension_result(
                            error_code.err().is_some_and(|error| {
                                error.code() == HRESULT::from_win32(ERROR_NOT_SUPPORTED)
                            }) && extension.is_none(),
                        );
                        Ok(())
                    }),
                );
                setup_probe.record_extension_attempt();
                match profile7.AddBrowserExtension(
                    &HSTRING::from(extension_path.as_path()),
                    &extension_handler,
                ) {
                    Ok(()) => {}
                    Err(error) if error.code() == HRESULT::from_win32(ERROR_NOT_SUPPORTED) => {
                        setup_probe.record_extension_result(true);
                    }
                    Err(error) => return Err(error),
                }
                Ok(())
            }
        })();
        probe.record_native_hardening_completed(result.is_ok());
    })
}

fn document_origin_is_allowed(url: &Url, allowed_proxy_origin: &Url) -> bool {
    let proxy_origin = url.scheme() == allowed_proxy_origin.scheme()
        && url.host_str() == allowed_proxy_origin.host_str()
        && url.port() == allowed_proxy_origin.port()
        && url.username().is_empty()
        && url.password().is_none();
    let bundled_placeholder =
        (url.scheme() == "tauri" && url.host_str() == Some("localhost") && url.port().is_none())
            || (url.scheme() == "http"
                && url.host_str() == Some("tauri.localhost")
                && url.port().is_none());
    proxy_origin || bundled_placeholder || url.as_str() == "about:blank"
}

/// Ask the real `WebView2` to navigate to the registered external scheme after
/// the page probe has finished. The previously attached handler must cancel it.
pub fn attempt_external_scheme(
    window: &WebviewWindow<Wry>,
    probe: Arc<BrowserEscapeProbe>,
) -> tauri::Result<()> {
    window.with_webview(move |platform| {
        // SAFETY: Tauri dispatches this closure on the WebView UI thread, and
        // the copied URI remains valid for the complete COM call.
        let result = unsafe {
            platform
                .controller()
                .CoreWebView2()
                .and_then(|core| core.Navigate(&HSTRING::from(EXTERNAL_SCHEME_PROBE_URI)))
        };
        probe.record_external_scheme_native_attempt(result.is_ok());
    })
}

/// Queue the exact bootstrap URL as a native `WebView2` request with one
/// one-time credential header.
pub fn navigate_with_bootstrap_header(
    window: &WebviewWindow<Wry>,
    url: Url,
    bootstrap: Arc<Secret>,
    queued: Arc<AtomicBool>,
) -> tauri::Result<()> {
    window.with_webview(move |platform| {
        let result = bootstrap.with_exposed(|value| {
            let header_text = Zeroizing::new(format!("{BOOTSTRAP_HEADER_NAME}: {value}\r\n"));
            let uri = HSTRING::from(url.as_str());
            let method = HSTRING::from("GET");
            let headers = HSTRING::from(header_text.as_str());

            // SAFETY: Tauri dispatches `with_webview` on the WebView UI
            // thread. Every COM interface comes from this exact pinned
            // WebView, the request owns copied HSTRING inputs, the method and
            // URI are fixed by native code, and no raw pointer escapes.
            unsafe {
                let environment: ICoreWebView2Environment2 = platform.environment().cast()?;
                let core = platform.controller().CoreWebView2()?;
                let core: ICoreWebView2_2 = core.cast()?;
                let request = environment.CreateWebResourceRequest(
                    &uri,
                    &method,
                    None::<&IStream>,
                    &headers,
                )?;
                core.NavigateWithWebResourceRequest(&request)
            }
        });
        queued.store(result.is_ok(), Ordering::SeqCst);
    })
}
