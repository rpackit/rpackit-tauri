//! Narrow audited `WebView2` bootstrap navigation boundary.
//!
//! Tauri does not currently expose initial-navigation headers. The one unsafe
//! block below calls the pinned `WebView2` COM API to create exactly one GET
//! request carrying the one-time bootstrap credential. No general request
//! interception or JavaScript bridge is installed.

#![allow(unsafe_code)]

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use rpackit_transport::{BOOTSTRAP_HEADER_NAME, Secret};
use tauri::{WebviewWindow, Wry};
use url::Url;
use webview2_com::Microsoft::Web::WebView2::Win32::{ICoreWebView2_2, ICoreWebView2Environment2};
use windows::{
    Win32::System::Com::IStream,
    core::{HSTRING, Interface as _},
};
use zeroize::Zeroizing;

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
