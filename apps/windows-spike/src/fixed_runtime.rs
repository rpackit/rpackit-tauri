//! Reviewed fixed-WebView2 runtime selection and identity verification.

use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, Metadata},
    io::{self, Read},
    path::{Component, Path, PathBuf},
    process::Command,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{Context, Wry, utils::config::WebviewInstallMode};

pub(crate) const FIXED_RUNTIME_ARGUMENT: &str = "--fixed-runtime";

const BROWSER_EXECUTABLE_FOLDER: &str = "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER";
const TREE_HASH_DOMAIN: &[u8] = b"rpackit-webview2-tree-v1\0";
const REPARSE_POINT_ATTRIBUTE: u32 = 0x400;
const MAX_RUNTIME_DIRECTORIES: usize = 32;
const MAX_RUNTIME_DEPTH: usize = 8;
const MAX_RELATIVE_PATH_BYTES: usize = 512;
const MANIFEST_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/webview2-fixed-runtime.json"
));

pub(crate) const FORBIDDEN_WEBVIEW_ENVIRONMENT_VARIABLES: &[&str] = &[
    "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
    BROWSER_EXECUTABLE_FOLDER,
    "WEBVIEW2_USER_DATA_FOLDER",
    "WEBVIEW2_CHANNEL_SEARCH_KIND",
    "WEBVIEW2_RELEASE_CHANNELS",
    "WEBVIEW2_RELEASE_CHANNEL_PREFERENCE",
    "WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER",
    "WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER",
];

#[derive(Clone, Debug, Deserialize)]
struct FixedRuntimeManifest {
    schema_version: u32,
    reviewed_on: String,
    architecture: String,
    api_capability_floor: String,
    api_capability_reason: String,
    supported_minimum_runtime: String,
    package_directory: String,
    official_download_page: String,
    archive_url: String,
    archive_file: String,
    archive_sha256: String,
    archive_bytes: u64,
    expanded_tree_sha256: String,
    expanded_file_count: usize,
    expanded_bytes: u64,
    tree_hash_algorithm: String,
    executable: String,
    executable_sha256: String,
    expected_signer_subject: String,
    expected_signer_thumbprint: String,
}

impl FixedRuntimeManifest {
    fn parse_reviewed() -> io::Result<Self> {
        let manifest: Self = serde_json::from_str(MANIFEST_JSON)
            .map_err(|_| io::Error::other("reviewed WebView2 manifest is invalid"))?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> io::Result<()> {
        if self.schema_version != 1
            || self.reviewed_on != "2026-07-26"
            || self.architecture != "x64"
            || self.tree_hash_algorithm != "rpackit-webview2-tree-v1"
            || self.expanded_file_count == 0
            || self.expanded_file_count > 1_000
            || self.expanded_bytes == 0
            || self.archive_bytes == 0
            || self.api_capability_reason.trim().is_empty()
            || self.expected_signer_subject
                != "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
            || !is_upper_hex_digest(&self.expected_signer_thumbprint, 40)
        {
            return Err(io::Error::other(
                "reviewed WebView2 manifest invariants do not hold",
            ));
        }
        for digest in [
            &self.archive_sha256,
            &self.expanded_tree_sha256,
            &self.executable_sha256,
        ] {
            if !is_lower_hex_digest(digest, 64) {
                return Err(io::Error::other(
                    "reviewed WebView2 manifest contains an invalid digest",
                ));
            }
        }
        let api_floor = parse_quad_version(&self.api_capability_floor)?;
        let supported_minimum = parse_quad_version(&self.supported_minimum_runtime)?;
        if api_floor > supported_minimum {
            return Err(io::Error::other(
                "supported WebView2 minimum is below the required API floor",
            ));
        }
        let expected_package_directory = format!(
            "Microsoft.WebView2.FixedVersionRuntime.{}.{}",
            self.supported_minimum_runtime, self.architecture
        );
        let expected_archive = format!("{expected_package_directory}.cab");
        if self.package_directory != expected_package_directory
            || self.archive_file != expected_archive
            || self.executable != "msedgewebview2.exe"
        {
            return Err(io::Error::other(
                "reviewed WebView2 package names are inconsistent",
            ));
        }
        let source = url::Url::parse(&self.archive_url)
            .map_err(|_| io::Error::other("reviewed WebView2 archive URL is invalid"))?;
        if source.scheme() != "https"
            || source.host_str() != Some("msedge.sf.dl.delivery.mp.microsoft.com")
            || source.path_segments().and_then(Iterator::last) != Some(self.archive_file.as_str())
        {
            return Err(io::Error::other(
                "reviewed WebView2 archive URL is not an approved Microsoft source",
            ));
        }
        let download_page = url::Url::parse(&self.official_download_page)
            .map_err(|_| io::Error::other("WebView2 download-page URL is invalid"))?;
        if download_page.scheme() != "https"
            || download_page.host_str() != Some("developer.microsoft.com")
        {
            return Err(io::Error::other(
                "WebView2 download page is not an approved Microsoft source",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ReviewedFixedRuntime {
    root: PathBuf,
    manifest: FixedRuntimeManifest,
    manifest_sha256: String,
}

/// Runtime evidence that can safely be serialized in the acceptance report.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Serialize)]
pub(crate) struct RuntimeEvidence {
    pub mode: &'static str,
    pub actual_version: Option<String>,
    pub architecture: Option<String>,
    pub api_capability_floor: Option<String>,
    pub supported_minimum_runtime: Option<String>,
    pub reviewed_on: Option<String>,
    pub official_download_page: Option<String>,
    pub archive_sha256: Option<String>,
    pub manifest_sha256: Option<String>,
    pub expanded_tree_sha256: Option<String>,
    pub expanded_file_count: Option<usize>,
    pub untrusted_environment_overrides_absent: bool,
    pub runtime_environment_matches_selection: bool,
    pub fixed_runtime_identity_verified: bool,
    pub actual_version_matches_supported_minimum: bool,
    pub reviewed_fixed_minimum_proven: bool,
}

impl Default for RuntimeEvidence {
    fn default() -> Self {
        Self {
            mode: "development",
            actual_version: None,
            architecture: None,
            api_capability_floor: None,
            supported_minimum_runtime: None,
            reviewed_on: None,
            official_download_page: None,
            archive_sha256: None,
            manifest_sha256: None,
            expanded_tree_sha256: None,
            expanded_file_count: None,
            untrusted_environment_overrides_absent: true,
            runtime_environment_matches_selection: true,
            fixed_runtime_identity_verified: false,
            actual_version_matches_supported_minimum: false,
            reviewed_fixed_minimum_proven: false,
        }
    }
}

/// Development runtime or the exact reviewed fixed runtime.
#[derive(Clone, Debug)]
pub(crate) enum RuntimeSelection {
    Development,
    ReviewedFixed(Box<ReviewedFixedRuntime>),
}

impl RuntimeSelection {
    pub(crate) fn prepare(fixed_root: Option<&Path>) -> io::Result<Self> {
        if !webview_environment_override_absent(|name| std::env::var_os(name).is_some()) {
            return Err(io::Error::other(
                "untrusted WebView2 environment override is not allowed",
            ));
        }
        let Some(root) = fixed_root else {
            return Ok(Self::Development);
        };
        let manifest = FixedRuntimeManifest::parse_reviewed()?;
        if std::env::consts::ARCH != "x86_64" {
            return Err(io::Error::other(
                "the reviewed fixed WebView2 runtime requires an x64 build",
            ));
        }
        let root = fs::canonicalize(root)
            .map_err(|_| io::Error::other("fixed WebView2 runtime path is unavailable"))?;
        verify_runtime_root(&root, &manifest)?;
        let manifest_sha256 = hex::encode(Sha256::digest(MANIFEST_JSON.as_bytes()));
        Ok(Self::ReviewedFixed(Box::new(ReviewedFixedRuntime {
            root,
            manifest,
            manifest_sha256,
        })))
    }

    pub(crate) fn configure_context(&self, context: &mut Context<Wry>) {
        if let Self::ReviewedFixed(runtime) = self {
            context.config_mut().bundle.windows.webview_install_mode =
                WebviewInstallMode::FixedRuntime {
                    path: runtime.root.clone(),
                };
        }
    }

    pub(crate) fn verify_configured_environment(&self) -> io::Result<()> {
        if self.runtime_environment_matches_selection() {
            Ok(())
        } else {
            Err(io::Error::other(
                "WebView2 runtime environment does not match the reviewed selection",
            ))
        }
    }

    pub(crate) fn append_child_arguments(&self, arguments: &mut Vec<OsString>) {
        if let Self::ReviewedFixed(runtime) = self {
            arguments.push(OsString::from(FIXED_RUNTIME_ARGUMENT));
            arguments.push(runtime.root.as_os_str().to_owned());
        }
    }

    pub(crate) fn scrub_child_environment(command: &mut Command) {
        for name in FORBIDDEN_WEBVIEW_ENVIRONMENT_VARIABLES {
            command.env_remove(name);
        }
    }

    pub(crate) fn evidence(&self, actual_version: Option<String>) -> RuntimeEvidence {
        let runtime_environment_matches_selection = self.runtime_environment_matches_selection();
        match self {
            Self::Development => RuntimeEvidence {
                actual_version,
                runtime_environment_matches_selection,
                ..RuntimeEvidence::default()
            },
            Self::ReviewedFixed(runtime) => {
                let actual_version_matches_supported_minimum = actual_version.as_deref()
                    == Some(runtime.manifest.supported_minimum_runtime.as_str());
                let reviewed_fixed_minimum_proven = runtime_environment_matches_selection
                    && actual_version_matches_supported_minimum;
                RuntimeEvidence {
                    mode: "reviewed-fixed",
                    actual_version,
                    architecture: Some(runtime.manifest.architecture.clone()),
                    api_capability_floor: Some(runtime.manifest.api_capability_floor.clone()),
                    supported_minimum_runtime: Some(
                        runtime.manifest.supported_minimum_runtime.clone(),
                    ),
                    reviewed_on: Some(runtime.manifest.reviewed_on.clone()),
                    official_download_page: Some(runtime.manifest.official_download_page.clone()),
                    archive_sha256: Some(runtime.manifest.archive_sha256.clone()),
                    manifest_sha256: Some(runtime.manifest_sha256.clone()),
                    expanded_tree_sha256: Some(runtime.manifest.expanded_tree_sha256.clone()),
                    expanded_file_count: Some(runtime.manifest.expanded_file_count),
                    untrusted_environment_overrides_absent: true,
                    runtime_environment_matches_selection,
                    fixed_runtime_identity_verified: true,
                    actual_version_matches_supported_minimum,
                    reviewed_fixed_minimum_proven,
                }
            }
        }
    }

    pub(crate) fn requires_release_gate(&self) -> bool {
        matches!(self, Self::ReviewedFixed(_))
    }

    fn runtime_environment_matches_selection(&self) -> bool {
        for name in FORBIDDEN_WEBVIEW_ENVIRONMENT_VARIABLES {
            let value = std::env::var_os(name);
            if *name == BROWSER_EXECUTABLE_FOLDER {
                match self {
                    Self::Development if value.is_some() => return false,
                    Self::ReviewedFixed(runtime)
                        if value.as_deref() != Some(runtime.root.as_os_str()) =>
                    {
                        return false;
                    }
                    _ => {}
                }
            } else if value.is_some() {
                return false;
            }
        }
        true
    }
}

pub(crate) fn webview_environment_override_absent(is_present: impl Fn(&str) -> bool) -> bool {
    !FORBIDDEN_WEBVIEW_ENVIRONMENT_VARIABLES
        .iter()
        .copied()
        .any(is_present)
}

fn verify_runtime_root(root: &Path, manifest: &FixedRuntimeManifest) -> io::Result<()> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir()
        || is_reparse_point(&metadata)
        || root.file_name() != Some(OsStr::new(&manifest.package_directory))
        || contains_edge_application_sequence(root)
    {
        return Err(io::Error::other(
            "fixed WebView2 runtime root is not safely scoped",
        ));
    }
    let mut files = Vec::with_capacity(manifest.expanded_file_count);
    let mut directory_count = 0;
    collect_runtime_files(root, root, 0, manifest, &mut directory_count, &mut files)?;
    files.sort_by(|left, right| left.relative.cmp(&right.relative));
    if files.len() != manifest.expanded_file_count {
        return Err(io::Error::other(
            "fixed WebView2 runtime file count does not match the reviewed package",
        ));
    }
    let expanded_bytes = files.iter().try_fold(0_u64, |total, file| {
        total
            .checked_add(file.length)
            .ok_or_else(|| io::Error::other("fixed WebView2 runtime size overflow"))
    })?;
    if expanded_bytes != manifest.expanded_bytes {
        return Err(io::Error::other(
            "fixed WebView2 runtime size does not match the reviewed package",
        ));
    }
    let tree_sha256 = hash_runtime_tree(&files)?;
    if tree_sha256 != manifest.expanded_tree_sha256 {
        return Err(io::Error::other(
            "fixed WebView2 runtime tree digest does not match the reviewed package",
        ));
    }
    let executable = root.join(&manifest.executable);
    if hash_file(&executable)? != manifest.executable_sha256 {
        return Err(io::Error::other(
            "fixed WebView2 executable digest does not match the reviewed package",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct RuntimeFile {
    relative: String,
    path: PathBuf,
    length: u64,
}

fn collect_runtime_files(
    root: &Path,
    directory: &Path,
    depth: usize,
    manifest: &FixedRuntimeManifest,
    directory_count: &mut usize,
    files: &mut Vec<RuntimeFile>,
) -> io::Result<()> {
    if depth > MAX_RUNTIME_DEPTH {
        return Err(io::Error::other(
            "fixed WebView2 runtime nesting is unexpectedly deep",
        ));
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if is_reparse_point(&metadata) {
            return Err(io::Error::other(
                "fixed WebView2 runtime contains a reparse point",
            ));
        }
        if metadata.is_dir() {
            *directory_count += 1;
            if *directory_count > MAX_RUNTIME_DIRECTORIES {
                return Err(io::Error::other(
                    "fixed WebView2 runtime contains too many directories",
                ));
            }
            collect_runtime_files(root, &path, depth + 1, manifest, directory_count, files)?;
        } else if metadata.is_file() {
            if files.len() >= manifest.expanded_file_count {
                return Err(io::Error::other(
                    "fixed WebView2 runtime contains too many files",
                ));
            }
            let relative = normalized_relative_path(root, &path)?;
            files.push(RuntimeFile {
                relative,
                path,
                length: metadata.len(),
            });
        } else {
            return Err(io::Error::other(
                "fixed WebView2 runtime contains an unsupported entry",
            ));
        }
    }
    Ok(())
}

fn normalized_relative_path(root: &Path, path: &Path) -> io::Result<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| io::Error::other("runtime path escaped its reviewed root"))?;
    let mut normalized = String::new();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(io::Error::other(
                "runtime path contains an unsafe component",
            ));
        };
        let part = part
            .to_str()
            .ok_or_else(|| io::Error::other("runtime path is not Unicode"))?;
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(part);
    }
    if normalized.is_empty() || normalized.len() > MAX_RELATIVE_PATH_BYTES {
        return Err(io::Error::other(
            "runtime relative path has an invalid length",
        ));
    }
    Ok(normalized)
}

fn hash_runtime_tree(files: &[RuntimeFile]) -> io::Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(TREE_HASH_DOMAIN);
    let mut buffer = vec![0_u8; 1024 * 1024];
    for runtime_file in files {
        let path_bytes = runtime_file.relative.as_bytes();
        let path_length = u32::try_from(path_bytes.len())
            .map_err(|_| io::Error::other("runtime relative path is too long"))?;
        hasher.update(path_length.to_le_bytes());
        hasher.update(path_bytes);
        hasher.update(runtime_file.length.to_le_bytes());
        let mut file = File::open(&runtime_file.path)?;
        let mut observed = 0_u64;
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            observed = observed
                .checked_add(read as u64)
                .ok_or_else(|| io::Error::other("runtime file size overflow"))?;
            hasher.update(&buffer[..read]);
        }
        if observed != runtime_file.length {
            return Err(io::Error::other(
                "runtime file changed while its identity was verified",
            ));
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn parse_quad_version(value: &str) -> io::Result<[u32; 4]> {
    let values = value
        .split('.')
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::other("WebView2 version is invalid"))?;
    <[u32; 4]>::try_from(values)
        .map_err(|_| io::Error::other("WebView2 version must have four components"))
}

fn is_lower_hex_digest(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_upper_hex_digest(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
}

fn contains_edge_application_sequence(path: &Path) -> bool {
    let components: Vec<_> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect();
    components.windows(2).any(|pair| {
        pair[0].eq_ignore_ascii_case("Edge") && pair[1].eq_ignore_ascii_case("Application")
    })
}

#[cfg(windows)]
fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE != 0
}

#[cfg(not(windows))]
fn is_reparse_point(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_manifest_is_internally_consistent() {
        let manifest = FixedRuntimeManifest::parse_reviewed();
        assert!(manifest.is_ok());
    }

    #[test]
    fn environment_detection_covers_every_forbidden_source() {
        assert!(webview_environment_override_absent(|_| false));
        for expected in FORBIDDEN_WEBVIEW_ENVIRONMENT_VARIABLES {
            assert!(!webview_environment_override_absent(
                |name| name == *expected
            ));
        }
    }

    #[test]
    fn quad_versions_are_orderable_and_strict() {
        assert!(
            parse_quad_version("120.0.2210.55").unwrap_or_default()
                < parse_quad_version("149.0.4022.98").unwrap_or_default()
        );
        assert!(parse_quad_version("149.0.4022").is_err());
        assert!(parse_quad_version("149.0.x.98").is_err());
    }

    #[test]
    fn unsafe_edge_application_path_is_detected_case_insensitively() {
        assert!(contains_edge_application_sequence(Path::new(
            r"C:\Edge\Application\runtime"
        )));
        assert!(!contains_edge_application_sequence(Path::new(
            r"C:\fixed\edge-runtime"
        )));
    }
}
