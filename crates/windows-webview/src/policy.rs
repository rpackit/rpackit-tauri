use std::{env, ffi::OsStr, io, path::Path};

use winreg::{
    RegKey,
    enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY},
};

use crate::WebviewError;

pub(crate) const MINIMUM_WEBVIEW2_VERSION: [u32; 4] = [149, 0, 4022, 98];

const FORBIDDEN_WEBVIEW_ENVIRONMENT_VARIABLES: &[&str] = &[
    "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
    "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER",
    "WEBVIEW2_USER_DATA_FOLDER",
    "WEBVIEW2_CHANNEL_SEARCH_KIND",
    "WEBVIEW2_RELEASE_CHANNELS",
    "WEBVIEW2_RELEASE_CHANNEL_PREFERENCE",
    "WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER",
    "WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER",
];

const WEBVIEW2_OVERRIDE_POLICY_KEYS: &[&str] = &[
    r"Software\Policies\Microsoft\Edge\WebView2\BrowserExecutableFolder",
    r"Software\Policies\Microsoft\Edge\WebView2\ChannelSearchKind",
    r"Software\Policies\Microsoft\Edge\WebView2\ReleaseChannels",
    r"Software\Policies\Microsoft\Edge\WebView2\AdditionalBrowserArguments",
    r"Software\Policies\Microsoft\Edge\WebView2\UserDataFolder",
    r"Software\Policies\Microsoft\Edge\WebView2\ReleaseChannelPreference",
];

pub(crate) fn verify(application_id: &str) -> Result<String, WebviewError> {
    if !application_id_is_valid(application_id) {
        return Err(WebviewError::InvalidApplicationIdentity);
    }
    if !environment_overrides_absent(|name| env::var_os(name).is_some()) {
        return Err(WebviewError::EnvironmentOverride);
    }
    let executable = env::current_exe().map_err(|_| WebviewError::ExecutableIdentity)?;
    if !registry_overrides_absent(application_id, &executable)
        .map_err(|_| WebviewError::RegistryInspection)?
    {
        return Err(WebviewError::RegistryOverride);
    }
    let actual = tauri::webview_version().map_err(|_| WebviewError::RuntimeUnavailable)?;
    if !version_is_supported(&actual) {
        return Err(WebviewError::RuntimeUnsupported);
    }
    Ok(actual)
}

fn application_id_is_valid(application_id: &str) -> bool {
    !application_id.is_empty()
        && application_id.len() <= 128
        && application_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn environment_overrides_absent(is_present: impl Fn(&str) -> bool) -> bool {
    !FORBIDDEN_WEBVIEW_ENVIRONMENT_VARIABLES
        .iter()
        .copied()
        .any(is_present)
}

fn registry_overrides_absent(application_id: &str, executable: &Path) -> io::Result<bool> {
    let app_ids = registry_app_ids(application_id, executable);
    let roots = [
        RegKey::predef(HKEY_LOCAL_MACHINE),
        RegKey::predef(HKEY_CURRENT_USER),
    ];
    let views = [KEY_WOW64_64KEY, KEY_WOW64_32KEY];
    for root in roots {
        for view in views {
            for subkey in WEBVIEW2_OVERRIDE_POLICY_KEYS {
                for app_id in &app_ids {
                    if registry_value_exists(&root, view, subkey, app_id)? {
                        return Ok(false);
                    }
                }
            }
        }
    }
    Ok(true)
}

fn registry_app_ids(application_id: &str, executable: &Path) -> Vec<String> {
    let mut app_ids = vec![application_id.to_owned()];
    if let Some(file_name) = executable.file_name().and_then(OsStr::to_str) {
        push_unique(&mut app_ids, file_name);
    }
    if let Some(file_stem) = executable.file_stem().and_then(OsStr::to_str) {
        push_unique(&mut app_ids, file_stem);
    }
    push_unique(&mut app_ids, "*");
    app_ids
}

fn push_unique(items: &mut Vec<String>, value: &str) {
    if !items.iter().any(|item| item.eq_ignore_ascii_case(value)) {
        items.push(value.to_owned());
    }
}

fn registry_value_exists(
    root: &RegKey,
    view: u32,
    subkey: &str,
    value_name: &str,
) -> io::Result<bool> {
    let key = match root.open_subkey_with_flags(subkey, KEY_READ | view) {
        Ok(key) => key,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    match key.get_raw_value(value_name) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn version_is_supported(version: &str) -> bool {
    parse_version(version).is_some_and(|actual| actual >= MINIMUM_WEBVIEW2_VERSION)
}

fn parse_version(version: &str) -> Option<[u32; 4]> {
    let mut parsed = [0_u32; 4];
    let mut components = version.split('.');
    for slot in &mut parsed {
        let component = components.next()?;
        if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        *slot = component.parse().ok()?;
    }
    if components.next().is_some() {
        return None;
    }
    Some(parsed)
}

#[cfg(test)]
mod tests {
    use super::{
        MINIMUM_WEBVIEW2_VERSION, application_id_is_valid, environment_overrides_absent,
        parse_version, registry_app_ids, version_is_supported,
    };
    use std::path::Path;

    #[test]
    fn runtime_version_parser_is_exact_and_ordered() {
        assert_eq!(
            parse_version("149.0.4022.98"),
            Some(MINIMUM_WEBVIEW2_VERSION)
        );
        assert!(version_is_supported("149.0.4022.98"));
        assert!(version_is_supported("150.0.0.0"));
        assert!(!version_is_supported("149.0.4022.97"));
        assert!(!version_is_supported("149.0.4022"));
        assert!(!version_is_supported("149.0.4022.98 dev"));
    }

    #[test]
    fn environment_override_check_covers_debug_and_runtime_selection() {
        assert!(environment_overrides_absent(|_| false));
        assert!(!environment_overrides_absent(|name| {
            name == "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER"
        }));
        assert!(!environment_overrides_absent(|name| {
            name == "WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER"
        }));
    }

    #[test]
    fn application_and_registry_id_inputs_are_bounded() {
        assert!(application_id_is_valid("dev.rpackit.shell"));
        assert!(!application_id_is_valid(""));
        assert!(!application_id_is_valid("dev.rpackit shell"));

        let ids = registry_app_ids(
            "dev.rpackit.shell",
            Path::new(r"C:\Program Files\rpackit\rpackit-windows-shell.exe"),
        );
        assert!(ids.iter().any(|item| item == "dev.rpackit.shell"));
        assert!(ids.iter().any(|item| item == "rpackit-windows-shell.exe"));
        assert!(ids.iter().any(|item| item == "rpackit-windows-shell"));
        assert!(ids.iter().any(|item| item == "*"));
    }
}
