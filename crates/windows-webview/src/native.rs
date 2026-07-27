//! Narrow audited WebView2 COM boundary.

#![allow(unsafe_code)]

use std::{sync::Arc, time::Duration};

use rpackit_transport::{BOOTSTRAP_HEADER_NAME, Secret};
use tauri::{WebviewWindow, Wry};
use tokio::sync::oneshot;
use url::Url;
use webview2_com::{
    LaunchingExternalUriSchemeEventHandler,
    Microsoft::Web::WebView2::Win32::{
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT, COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT,
        ICoreWebView2_2, ICoreWebView2_18, ICoreWebView2Environment2, ICoreWebView2Settings3,
    },
    WebResourceRequestedEventHandler, take_pwstr,
};
use windows::{
    Win32::System::Com::IStream,
    core::{BOOL, HSTRING, Interface as _, PWSTR},
};
use zeroize::Zeroizing;

use crate::WebviewError;

pub(crate) async fn install_guards(
    window: &WebviewWindow<Wry>,
    allowed_proxy_origin: Url,
    operation_timeout: Duration,
) -> Result<(), WebviewError> {
    let (sender, receiver) = oneshot::channel();
    window
        .with_webview(move |platform| {
            let installed = (|| -> windows::core::Result<()> {
                // SAFETY: Tauri dispatches this closure and every registered
                // callback on the WebView UI thread. All COM interfaces come
                // from this exact controller, copied strings outlive their
                // calls, registered handlers are retained by WebView2, and no
                // raw pointer escapes.
                unsafe {
                    let core = platform.controller().CoreWebView2()?;
                    let settings = core.Settings()?;
                    settings.SetAreDevToolsEnabled(false)?;
                    settings.SetAreDefaultContextMenusEnabled(false)?;
                    settings.SetIsStatusBarEnabled(false)?;
                    let settings3: ICoreWebView2Settings3 = settings.cast()?;
                    settings3.SetAreBrowserAcceleratorKeysEnabled(false)?;

                    let mut devtools_enabled = BOOL::default();
                    let mut context_menus_enabled = BOOL::default();
                    let mut status_bar_enabled = BOOL::default();
                    let mut browser_accelerators_enabled = BOOL::default();
                    settings.AreDevToolsEnabled(&raw mut devtools_enabled)?;
                    settings.AreDefaultContextMenusEnabled(&raw mut context_menus_enabled)?;
                    settings.IsStatusBarEnabled(&raw mut status_bar_enabled)?;
                    settings3
                        .AreBrowserAcceleratorKeysEnabled(&raw mut browser_accelerators_enabled)?;
                    if devtools_enabled.as_bool()
                        || context_menus_enabled.as_bool()
                        || status_bar_enabled.as_bool()
                        || browser_accelerators_enabled.as_bool()
                    {
                        return Err(windows::core::Error::from_hresult(windows::core::HRESULT(
                            0x8000_4005_u32.cast_signed(),
                        )));
                    }

                    let resource_environment = platform.environment().clone();
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
                            args.SetResponse(&response)
                        }));
                    core.AddWebResourceRequestedFilter(
                        &HSTRING::from("*"),
                        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT,
                    )?;
                    let mut resource_token = 0_i64;
                    core.add_WebResourceRequested(&resource_handler, &raw mut resource_token)?;

                    let external_handler =
                        LaunchingExternalUriSchemeEventHandler::create(Box::new(move |_, args| {
                            if let Some(args) = args {
                                args.SetCancel(true)?;
                            }
                            Ok(())
                        }));
                    let core18: ICoreWebView2_18 = core.cast()?;
                    let mut external_token = 0_i64;
                    core18.add_LaunchingExternalUriScheme(
                        &external_handler,
                        &raw mut external_token,
                    )?;
                    Ok(())
                }
            })();
            let _ = sender.send(installed.is_ok());
        })
        .map_err(|_| WebviewError::NativeGuardScheduling)?;

    let installed = tokio::time::timeout(operation_timeout, receiver)
        .await
        .map_err(|_| WebviewError::NativeGuardTimeout)?
        .map_err(|_| WebviewError::NativeGuardChannel)?;
    if installed {
        Ok(())
    } else {
        Err(WebviewError::NativeGuardFailure)
    }
}

pub(crate) async fn navigate_with_bootstrap(
    window: &WebviewWindow<Wry>,
    url: Url,
    bootstrap: Arc<Secret>,
    operation_timeout: Duration,
) -> Result<(), WebviewError> {
    let (sender, receiver) = oneshot::channel();
    window
        .with_webview(move |platform| {
            let navigated = bootstrap.with_exposed(|value| {
                let header_text = Zeroizing::new(format!("{BOOTSTRAP_HEADER_NAME}: {value}\r\n"));
                let uri = HSTRING::from(url.as_str());
                let method = HSTRING::from("GET");
                let headers = HSTRING::from(header_text.as_str());

                // SAFETY: Tauri dispatches this closure on the WebView UI
                // thread. Every interface comes from this exact WebView, the
                // request owns copied strings, the URI/method are native
                // constants, and no raw pointer escapes.
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
            let _ = sender.send(navigated.is_ok());
        })
        .map_err(|_| WebviewError::BootstrapScheduling)?;

    let navigated = tokio::time::timeout(operation_timeout, receiver)
        .await
        .map_err(|_| WebviewError::BootstrapTimeout)?
        .map_err(|_| WebviewError::BootstrapChannel)?;
    if navigated {
        Ok(())
    } else {
        Err(WebviewError::BootstrapFailure)
    }
}

fn document_origin_is_allowed(url: &Url, allowed_proxy_origin: &Url) -> bool {
    same_origin(url, allowed_proxy_origin)
        || is_bundled_placeholder(url)
        || url.as_str() == "about:blank"
}

fn same_origin(url: &Url, expected: &Url) -> bool {
    url.scheme() == expected.scheme()
        && url.host_str() == expected.host_str()
        && url.port() == expected.port()
        && url.username().is_empty()
        && url.password().is_none()
}

fn is_bundled_placeholder(url: &Url) -> bool {
    let bundled_origin =
        (url.scheme() == "tauri" && url.host_str() == Some("localhost") && url.port().is_none())
            || (url.scheme() == "http"
                && url.host_str() == Some("tauri.localhost")
                && url.port().is_none());
    bundled_origin
        && url.path() == "/index.html"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}

#[cfg(test)]
mod tests {
    use super::{document_origin_is_allowed, same_origin};
    use url::Url;

    #[test]
    fn only_the_exact_proxy_origin_and_native_placeholder_are_allowed()
    -> Result<(), url::ParseError> {
        let root = Url::parse("http://rpackit-abcd.localhost:43123/")?;
        assert!(same_origin(
            &Url::parse("http://rpackit-abcd.localhost:43123/path")?,
            &root
        ));
        assert!(!same_origin(
            &Url::parse("http://rpackit-abcd.localhost:43124/")?,
            &root
        ));
        assert!(!same_origin(
            &Url::parse("http://child.rpackit-abcd.localhost:43123/")?,
            &root
        ));
        assert!(document_origin_is_allowed(
            &Url::parse("tauri://localhost/index.html")?,
            &root
        ));
        assert!(document_origin_is_allowed(
            &Url::parse("about:blank")?,
            &root
        ));
        assert!(!document_origin_is_allowed(
            &Url::parse("https://example.invalid/")?,
            &root
        ));
        Ok(())
    }
}
