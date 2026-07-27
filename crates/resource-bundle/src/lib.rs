//! Fail-closed validation of prepared rpackit desktop resource bundles.
//!
//! Validation is non-executing: no bundled R code, application code, or
//! launcher code runs. The validator accepts only the current schema-1,
//! protocol-2 Windows contract and resolves every critical manifest path
//! beneath the canonical `resources` directory.

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;
use url::Url;

const MANIFEST_FILE: &str = "rpackit.json";
const RESOURCES_DIRECTORY: &str = "resources";
const MANIFEST_MAX_BYTES: u64 = 256 * 1024;
const LAUNCHER_MAX_BYTES: u64 = 256 * 1024;
const MAX_PACKAGES: usize = 4_096;
const MAX_CONSTRAINTS: usize = 4_096;
const MAX_SHORT_TEXT_BYTES: usize = 256;
const MAX_REQUIREMENT_BYTES: usize = 512;
const MAX_URL_BYTES: usize = 4_096;

/// Supported Shiny application layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppType {
    /// One `app/app.R` entry point.
    SingleFile,
    /// Separate `app/ui.R` and `app/server.R` entry points.
    Split,
}

/// Provenance mode recorded by the resource manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeSource {
    /// A caller-supplied portable runtime without registry provenance.
    Explicit,
    /// A runtime resolved from the verified rpackit registry.
    Registry,
}

/// A schema-1 Windows bundle whose critical resources passed validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedBundle {
    bundle: PathBuf,
    resources: PathBuf,
    manifest: PathBuf,
    rscript: PathBuf,
    library: PathBuf,
    app: PathBuf,
    launcher: PathBuf,
    app_type: AppType,
    runtime_source: RuntimeSource,
    runtime_version: Option<String>,
    packages: Vec<String>,
    created_by_version: String,
}

impl ValidatedBundle {
    /// Validates a prepared bundle without executing any bundled content.
    ///
    /// The accepted native-launch subset requires a current schema-1 Windows
    /// bundle, protocol 2, authenticated Shiny transport, installed and
    /// constraint-verified packages, fixed resource topology, and a launcher
    /// containing the security markers emitted by current rpackit.
    ///
    /// # Errors
    ///
    /// Returns a secret-free error for malformed or oversized input, an
    /// unsupported contract, unsafe/reparse paths, missing resources, an
    /// incomplete runtime or dependency library, or a launcher mismatch.
    pub fn load(bundle: impl AsRef<Path>) -> Result<Self, BundleError> {
        let bundle = canonical_bundle_root(bundle.as_ref())?;
        let resources = direct_resources_directory(&bundle)?;
        let manifest_path = resources.join(MANIFEST_FILE);
        let manifest_bytes = read_bounded_regular_file(
            &manifest_path,
            MANIFEST_MAX_BYTES,
            "read resource manifest",
        )?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|_| BundleError::InvalidManifestJson)?;
        let semantics = validate_manifest(&manifest)?;

        let rscript = resolve_manifest_path(
            &resources,
            &manifest.runtime.rscript,
            "runtime.rscript",
            RequiredKind::File,
        )?;
        let library = resolve_manifest_path(
            &resources,
            &manifest.runtime.library,
            "runtime.library",
            RequiredKind::Directory,
        )?;
        let app = resolve_manifest_path(
            &resources,
            &manifest.app.path,
            "app.path",
            RequiredKind::Directory,
        )?;
        let launcher = resolve_manifest_path(
            &resources,
            &manifest.launcher.script,
            "launcher.script",
            RequiredKind::File,
        )?;
        let runtime_root = resolve_manifest_path(
            &resources,
            &manifest.runtime.path,
            "runtime.path",
            RequiredKind::Directory,
        )?;
        if !rscript.starts_with(&runtime_root) || !library.starts_with(&runtime_root) {
            return Err(BundleError::UnsafeManifestPath("runtime"));
        }

        validate_app_layout(&app, semantics.app_type)?;
        validate_installed_packages(&library, &manifest.dependencies.packages)?;
        validate_launcher_file(&launcher)?;

        Ok(Self {
            bundle,
            resources,
            manifest: manifest_path,
            rscript,
            library,
            app,
            launcher,
            app_type: semantics.app_type,
            runtime_source: semantics.runtime_source,
            runtime_version: manifest.runtime.r_version,
            packages: manifest.dependencies.packages,
            created_by_version: manifest.created_by.version,
        })
    }

    /// Returns the canonical bundle root.
    #[must_use]
    pub fn bundle(&self) -> &Path {
        &self.bundle
    }

    /// Returns the canonical `resources` directory.
    #[must_use]
    pub fn resources(&self) -> &Path {
        &self.resources
    }

    /// Returns the validated manifest path.
    #[must_use]
    pub fn manifest(&self) -> &Path {
        &self.manifest
    }

    /// Returns the bundled absolute `Rscript.exe` path.
    #[must_use]
    pub fn rscript(&self) -> &Path {
        &self.rscript
    }

    /// Returns the bundled runtime-library directory.
    #[must_use]
    pub fn library(&self) -> &Path {
        &self.library
    }

    /// Returns the bundled Shiny application directory.
    #[must_use]
    pub fn app(&self) -> &Path {
        &self.app
    }

    /// Returns the generated protocol-2 launcher path.
    #[must_use]
    pub fn launcher(&self) -> &Path {
        &self.launcher
    }

    /// Returns the verified application layout.
    #[must_use]
    pub const fn app_type(&self) -> AppType {
        self.app_type
    }

    /// Returns the recorded portable-runtime source mode.
    #[must_use]
    pub const fn runtime_source(&self) -> RuntimeSource {
        self.runtime_source
    }

    /// Returns the recorded R version when present.
    #[must_use]
    pub fn runtime_version(&self) -> Option<&str> {
        self.runtime_version.as_deref()
    }

    /// Returns the unique package names verified in the runtime library.
    #[must_use]
    pub fn packages(&self) -> &[String] {
        &self.packages
    }

    /// Returns the rpackit version that created the bundle.
    #[must_use]
    pub fn created_by_version(&self) -> &str {
        &self.created_by_version
    }
}

#[derive(Clone, Copy)]
struct ManifestSemantics {
    app_type: AppType,
    runtime_source: RuntimeSource,
}

fn validate_manifest(manifest: &Manifest) -> Result<ManifestSemantics, BundleError> {
    if manifest.schema_version != "1" || manifest.bundle_type != "rpackit-desktop-resources" {
        return Err(BundleError::UnsupportedResourceContract);
    }
    validate_short_text(&manifest.app.name)?;
    let app_type = match manifest.app.app_type.as_str() {
        "shiny-single-file" => AppType::SingleFile,
        "shiny-split" => AppType::Split,
        _ => return Err(BundleError::UnsupportedApplicationLayout),
    };
    if manifest.app.path != "app" {
        return Err(BundleError::UnsafeManifestPath("app.path"));
    }

    let runtime_source = validate_runtime_manifest(&manifest.runtime)?;
    validate_launcher_manifest(&manifest.launcher)?;
    validate_dependency_manifest(&manifest.dependencies)?;
    if manifest.created_by.package != "rpackit" || !valid_version_text(&manifest.created_by.version)
    {
        return Err(BundleError::InvalidCreator);
    }

    Ok(ManifestSemantics {
        app_type,
        runtime_source,
    })
}

fn validate_runtime_manifest(runtime: &RuntimeManifest) -> Result<RuntimeSource, BundleError> {
    if runtime.path != "R"
        || runtime.rscript != "R/bin/Rscript.exe"
        || runtime.library != "R/library"
        || runtime.platform != "windows"
    {
        return Err(BundleError::UnsupportedRuntimeContract);
    }
    if let Some(version) = &runtime.r_version
        && !valid_version_text(version)
    {
        return Err(BundleError::UnsupportedRuntimeContract);
    }

    match runtime.source.as_str() {
        "explicit" if runtime.provenance.is_none() => Ok(RuntimeSource::Explicit),
        "registry" => {
            let Some(provenance) = runtime.provenance.as_ref() else {
                return Err(BundleError::InvalidRuntimeProvenance);
            };
            if runtime.r_version.is_none() {
                return Err(BundleError::InvalidRuntimeProvenance);
            }
            validate_provenance(provenance)?;
            Ok(RuntimeSource::Registry)
        }
        _ => Err(BundleError::InvalidRuntimeProvenance),
    }
}

fn validate_provenance(provenance: &RuntimeProvenance) -> Result<(), BundleError> {
    if provenance.archive_format != "zip"
        || provenance.sha256.len() != 64
        || !provenance
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || !valid_source_reference(&provenance.registry)
        || !valid_source_reference(&provenance.metadata_source)
        || !valid_source_reference(&provenance.artifact_url)
        || (is_https_reference(&provenance.registry)
            && (!is_https_reference(&provenance.metadata_source)
                || !is_https_reference(&provenance.artifact_url)))
    {
        return Err(BundleError::InvalidRuntimeProvenance);
    }
    let _ = provenance.cache_hit;
    Ok(())
}

fn validate_launcher_manifest(launcher: &LauncherManifest) -> Result<(), BundleError> {
    if launcher.script != "launcher.R"
        || launcher.host != "127.0.0.1"
        || launcher.port != "required-argument"
        || launcher.token != "private-file"
        || launcher.control != "optional-argument"
        || launcher.protocol_version != "2"
        || launcher.event_stream.format != "ndjson"
        || launcher.event_stream.destination != "stdout"
        || launcher.event_stream.prefix != "RPACKIT_EVENT "
        || !launcher.network_token_enforced
        || launcher.authentication.scheme != "shiny-shared-secret"
        || launcher.authentication.header != "Shiny-Shared-Secret"
        || launcher.authentication.scope != ["http", "websocket"]
        || launcher.authentication.token_transport != "private-file"
        || launcher.authentication.token_in_url
        || launcher.authentication.minimum_shiny_version != "1.3.0"
        || launcher.readiness.strategy != "authenticated-http-poll"
        || launcher.readiness.starting_event != "listening"
    {
        return Err(BundleError::UnsupportedLauncherContract);
    }
    Ok(())
}

fn validate_dependency_manifest(dependencies: &DependencyManifest) -> Result<(), BundleError> {
    if !dependencies.installed
        || !dependencies.constraints_verified
        || !matches!(
            dependencies.strategy.as_str(),
            "install-packages" | "renv-restore"
        )
        || dependencies.packages.is_empty()
        || dependencies.packages.len() > MAX_PACKAGES
        || dependencies.constraints.len() > MAX_CONSTRAINTS
    {
        return Err(BundleError::IncompleteDependencies);
    }
    if dependencies
        .packages
        .iter()
        .any(|package| !valid_package_name(package))
    {
        return Err(BundleError::InvalidDependencies);
    }
    let packages: HashSet<&str> = dependencies.packages.iter().map(String::as_str).collect();
    if packages.len() != dependencies.packages.len() {
        return Err(BundleError::InvalidDependencies);
    }
    for required in ["jsonlite", "later", "shiny"] {
        if !packages.contains(required) {
            return Err(BundleError::IncompleteDependencies);
        }
    }
    validate_optional_requirement(dependencies.locked_r_version.as_deref())?;
    validate_optional_requirement(dependencies.r_constraint.as_deref())?;

    let mut constraints = HashSet::with_capacity(dependencies.constraints.len());
    for constraint in &dependencies.constraints {
        if !valid_package_name(&constraint.package)
            || !packages.contains(constraint.package.as_str())
            || !valid_requirement(&constraint.requirement)
            || !constraints.insert((constraint.package.as_str(), constraint.requirement.as_str()))
        {
            return Err(BundleError::InvalidDependencies);
        }
    }
    Ok(())
}

fn validate_app_layout(app: &Path, app_type: AppType) -> Result<(), BundleError> {
    match app_type {
        AppType::SingleFile => {
            critical_child(app, "app.R", "app.app.R", RequiredKind::File)?;
        }
        AppType::Split => {
            if critical_child_exists(app, "app.R", "app.app.R", RequiredKind::File)? {
                return Err(BundleError::ApplicationLayoutMismatch);
            }
            critical_child(app, "ui.R", "app.ui.R", RequiredKind::File)?;
            critical_child(app, "server.R", "app.server.R", RequiredKind::File)?;
        }
    }
    Ok(())
}

fn validate_installed_packages(library: &Path, packages: &[String]) -> Result<(), BundleError> {
    for package in packages {
        let package_directory =
            critical_child(library, package, "runtime.package", RequiredKind::Directory)?;
        critical_child(
            &package_directory,
            "DESCRIPTION",
            "runtime.package.DESCRIPTION",
            RequiredKind::File,
        )?;
    }
    Ok(())
}

fn validate_launcher_file(path: &Path) -> Result<(), BundleError> {
    let bytes = read_bounded_regular_file(path, LAUNCHER_MAX_BYTES, "read launcher")?;
    let launcher = std::str::from_utf8(&bytes).map_err(|_| BundleError::InvalidLauncherText)?;
    if launcher.contains('\0') {
        return Err(BundleError::InvalidLauncherText);
    }
    let required = [
        "event_prefix <- 'RPACKIT_EVENT '",
        "protocol_version = '2'",
        "--token-file <path>",
        "readLines(token_file, n = 2L",
        "unlink(token_file, force = TRUE)",
        "options(shiny.sharedSecret = token)",
        "rpackit_authenticated_app_path",
        "token_enforced = TRUE",
        "host = '127.0.0.1'",
        "launch.browser = announce_listening",
    ];
    let forbidden = [
        "0.0.0.0",
        "RPACKIT_SESSION_TOKEN",
        "?rpackit_token=",
        "--token <token>",
        "token_enforced = FALSE",
    ];
    if required.iter().any(|marker| !launcher.contains(marker))
        || forbidden.iter().any(|marker| launcher.contains(marker))
    {
        return Err(BundleError::LauncherContractMismatch);
    }
    Ok(())
}

fn canonical_bundle_root(path: &Path) -> Result<PathBuf, BundleError> {
    if !path.is_absolute() {
        return Err(BundleError::InvalidBundleRoot);
    }
    let metadata = metadata_without_link(path, "bundle")?;
    require_kind(&metadata, RequiredKind::Directory, "bundle")?;
    fs::canonicalize(path).map_err(|source| BundleError::FileSystem {
        operation: "canonicalize bundle",
        source,
    })
}

fn direct_resources_directory(bundle: &Path) -> Result<PathBuf, BundleError> {
    let resources = bundle.join(RESOURCES_DIRECTORY);
    let metadata = metadata_without_link(&resources, "resources")?;
    require_kind(&metadata, RequiredKind::Directory, "resources")?;
    let resources = fs::canonicalize(resources).map_err(|source| BundleError::FileSystem {
        operation: "canonicalize resources",
        source,
    })?;
    if resources.parent() != Some(bundle) {
        return Err(BundleError::UnsafeManifestPath("resources"));
    }
    Ok(resources)
}

fn resolve_manifest_path(
    resources: &Path,
    value: &str,
    field: &'static str,
    kind: RequiredKind,
) -> Result<PathBuf, BundleError> {
    let components = safe_posix_components(value).ok_or(BundleError::UnsafeManifestPath(field))?;
    let mut path = resources.to_path_buf();
    for component in components {
        path.push(component);
        let _ = metadata_without_link(&path, field)?;
    }
    let metadata = metadata_without_link(&path, field)?;
    require_kind(&metadata, kind, field)?;
    let path = fs::canonicalize(path).map_err(|source| BundleError::FileSystem {
        operation: "canonicalize manifest path",
        source,
    })?;
    if path == resources || !path.starts_with(resources) {
        return Err(BundleError::UnsafeManifestPath(field));
    }
    Ok(path)
}

fn critical_child(
    directory: &Path,
    leaf: &str,
    field: &'static str,
    kind: RequiredKind,
) -> Result<PathBuf, BundleError> {
    if !valid_leaf(leaf) {
        return Err(BundleError::UnsafeManifestPath(field));
    }
    let path = directory.join(leaf);
    let metadata = metadata_without_link(&path, field)?;
    require_kind(&metadata, kind, field)?;
    Ok(path)
}

fn critical_child_exists(
    directory: &Path,
    leaf: &str,
    field: &'static str,
    kind: RequiredKind,
) -> Result<bool, BundleError> {
    if !valid_leaf(leaf) {
        return Err(BundleError::UnsafeManifestPath(field));
    }
    let path = directory.join(leaf);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(BundleError::FileSystem {
                operation: "inspect optional critical resource",
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || windows_reparse_point(&metadata) {
        return Err(BundleError::ReparsePoint(field));
    }
    require_kind(&metadata, kind, field)?;
    Ok(true)
}

fn read_bounded_regular_file(
    path: &Path,
    maximum: u64,
    operation: &'static str,
) -> Result<Vec<u8>, BundleError> {
    let metadata = metadata_without_link(path, operation)?;
    require_kind(&metadata, RequiredKind::File, operation)?;
    if metadata.len() > maximum {
        return Err(BundleError::ResourceTooLarge(operation));
    }
    let file = File::open(path).map_err(|source| BundleError::FileSystem { operation, source })?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| BundleError::FileSystem { operation, source })?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > maximum) {
        return Err(BundleError::ResourceTooLarge(operation));
    }
    Ok(bytes)
}

fn metadata_without_link(path: &Path, field: &'static str) -> Result<Metadata, BundleError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| BundleError::FileSystem {
        operation: "inspect critical resource",
        source,
    })?;
    if metadata.file_type().is_symlink() || windows_reparse_point(&metadata) {
        return Err(BundleError::ReparsePoint(field));
    }
    Ok(metadata)
}

#[cfg(windows)]
fn windows_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn windows_reparse_point(_metadata: &Metadata) -> bool {
    false
}

#[derive(Clone, Copy)]
enum RequiredKind {
    File,
    Directory,
}

fn require_kind(
    metadata: &Metadata,
    kind: RequiredKind,
    field: &'static str,
) -> Result<(), BundleError> {
    let matches = match kind {
        RequiredKind::File => metadata.is_file(),
        RequiredKind::Directory => metadata.is_dir(),
    };
    if !matches {
        return Err(BundleError::WrongResourceType(field));
    }
    Ok(())
}

fn safe_posix_components(value: &str) -> Option<Vec<&str>> {
    if value.is_empty()
        || value.len() > 1_024
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.contains(':')
        || value.chars().any(char::is_control)
    {
        return None;
    }
    let components: Vec<&str> = value.split('/').collect();
    if components
        .iter()
        .any(|component| component.is_empty() || matches!(*component, "." | ".."))
    {
        return None;
    }
    Some(components)
}

fn valid_leaf(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SHORT_TEXT_BYTES
        && !value.contains(['/', '\\', ':'])
        && !matches!(value, "." | "..")
        && !value.chars().any(char::is_control)
}

fn valid_package_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
        && value.len() <= MAX_SHORT_TEXT_BYTES
}

fn validate_short_text(value: &str) -> Result<(), BundleError> {
    if value.is_empty() || value.len() > MAX_SHORT_TEXT_BYTES || value.chars().any(char::is_control)
    {
        return Err(BundleError::InvalidManifestText);
    }
    Ok(())
}

fn valid_version_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SHORT_TEXT_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'))
}

fn validate_optional_requirement(value: Option<&str>) -> Result<(), BundleError> {
    if value.is_some_and(|requirement| !valid_requirement(requirement)) {
        return Err(BundleError::InvalidDependencies);
    }
    Ok(())
}

fn valid_requirement(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REQUIREMENT_BYTES
        && value
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
}

fn valid_https_url(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_URL_BYTES || value.chars().any(char::is_control) {
        return false;
    }
    Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.has_host()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn is_https_reference(value: &str) -> bool {
    value
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
}

fn valid_source_reference(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_URL_BYTES || value.chars().any(char::is_control) {
        return false;
    }
    if is_https_reference(value) {
        return valid_https_url(value);
    }
    if value.starts_with(r"\\")
        || value.starts_with("//")
        || value.contains(['?', '#'])
        || has_non_file_url_scheme(value)
    {
        return false;
    }
    true
}

fn has_non_file_url_scheme(value: &str) -> bool {
    let Some(colon) = value.find(':') else {
        return false;
    };
    let prefix = &value[..colon];
    let windows_drive = prefix.len() == 1
        && prefix.bytes().all(|byte| byte.is_ascii_alphabetic())
        && value
            .as_bytes()
            .get(colon + 1)
            .is_some_and(|byte| matches!(*byte, b'/' | b'\\'));
    !windows_drive
        && !prefix.is_empty()
        && prefix
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        && prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'-'))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: String,
    bundle_type: String,
    app: AppManifest,
    runtime: RuntimeManifest,
    launcher: LauncherManifest,
    dependencies: DependencyManifest,
    created_by: CreatedByManifest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppManifest {
    name: String,
    #[serde(rename = "type")]
    app_type: String,
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeManifest {
    path: String,
    rscript: String,
    library: String,
    platform: String,
    r_version: Option<String>,
    source: String,
    provenance: Option<RuntimeProvenance>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeProvenance {
    registry: String,
    metadata_source: String,
    artifact_url: String,
    sha256: String,
    archive_format: String,
    cache_hit: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LauncherManifest {
    script: String,
    host: String,
    port: String,
    token: String,
    control: String,
    protocol_version: String,
    event_stream: EventStreamManifest,
    network_token_enforced: bool,
    authentication: AuthenticationManifest,
    readiness: ReadinessManifest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventStreamManifest {
    format: String,
    destination: String,
    prefix: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticationManifest {
    scheme: String,
    header: String,
    scope: Vec<String>,
    token_transport: String,
    token_in_url: bool,
    minimum_shiny_version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadinessManifest {
    strategy: String,
    starting_event: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyManifest {
    installed: bool,
    strategy: String,
    packages: Vec<String>,
    locked_r_version: Option<String>,
    r_constraint: Option<String>,
    constraints: Vec<DependencyConstraint>,
    constraints_verified: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyConstraint {
    package: String,
    requirement: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatedByManifest {
    package: String,
    version: String,
}

/// Secret-free resource-validation error.
#[derive(Debug, Error)]
pub enum BundleError {
    /// The bundle root must be an existing absolute directory.
    #[error("the bundle root was not an existing absolute directory")]
    InvalidBundleRoot,
    /// The JSON manifest was malformed, ambiguous, or contained unknown fields.
    #[error("the resource manifest was not valid strict JSON")]
    InvalidManifestJson,
    /// Only the current schema-1 resource contract is accepted.
    #[error("the resource manifest contract was unsupported")]
    UnsupportedResourceContract,
    /// Only current authenticated protocol-2 launch metadata is accepted.
    #[error("the launcher manifest contract was unsupported")]
    UnsupportedLauncherContract,
    /// Only the bundled Windows portable-runtime layout is accepted.
    #[error("the runtime manifest contract was unsupported")]
    UnsupportedRuntimeContract,
    /// Registry provenance was absent or malformed.
    #[error("the runtime provenance was invalid")]
    InvalidRuntimeProvenance,
    /// The application layout name was unsupported.
    #[error("the application layout was unsupported")]
    UnsupportedApplicationLayout,
    /// The application files did not match the declared layout.
    #[error("the application files did not match the manifest")]
    ApplicationLayoutMismatch,
    /// Installed and verified dependency evidence is required for native launch.
    #[error("the resource bundle dependencies were incomplete")]
    IncompleteDependencies,
    /// Package names, duplicates, or constraints were malformed.
    #[error("the resource bundle dependencies were invalid")]
    InvalidDependencies,
    /// Creator identity or version was malformed.
    #[error("the resource-bundle creator was invalid")]
    InvalidCreator,
    /// A manifest text field was empty, oversized, or contained controls.
    #[error("the resource manifest contained invalid text")]
    InvalidManifestText,
    /// A relative manifest path escaped or used unsafe Windows syntax.
    #[error("manifest field {0} was not a safe resource-relative path")]
    UnsafeManifestPath(&'static str),
    /// A critical path was a symbolic link, junction, or other reparse point.
    #[error("critical resource {0} was a link or reparse point")]
    ReparsePoint(&'static str),
    /// A critical resource was not the required file/directory type.
    #[error("critical resource {0} had the wrong type")]
    WrongResourceType(&'static str),
    /// A bounded manifest or launcher exceeded its maximum.
    #[error("resource read {0} exceeded its byte limit")]
    ResourceTooLarge(&'static str),
    /// The launcher was not strict UTF-8 text.
    #[error("the launcher was not valid bounded UTF-8 text")]
    InvalidLauncherText,
    /// The launcher did not contain the current protocol-2 security markers.
    #[error("the launcher did not match its authenticated protocol-2 contract")]
    LauncherContractMismatch,
    /// A filesystem operation failed without exposing untrusted path content.
    #[error("{operation} failed: {source}")]
    FileSystem {
        /// Bounded operation that failed.
        operation: &'static str,
        /// Underlying operating-system error.
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::{AppType, BundleError, RuntimeSource, ValidatedBundle};

    const VALID_LAUNCHER: &str = r"
event_prefix <- 'RPACKIT_EVENT '
payload <- list(protocol_version = '2')
usage <- '--token-file <path>'
token_lines <- readLines(token_file, n = 2L, warn = FALSE)
unlink(token_file, force = TRUE)
options(shiny.sharedSecret = token)
class(app) <- 'rpackit_authenticated_app_path'
token_enforced = TRUE
host = '127.0.0.1'
launch.browser = announce_listening
";

    struct Fixture {
        _temporary: TempDir,
        bundle: PathBuf,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let temporary = tempfile::tempdir()?;
            let bundle = temporary.path().join("bundle with spaces");
            let resources = bundle.join("resources");
            fs::create_dir_all(resources.join("R/bin"))?;
            fs::create_dir_all(resources.join("R/library"))?;
            fs::create_dir_all(resources.join("app"))?;
            fs::write(resources.join("R/bin/Rscript.exe"), b"MZ")?;
            fs::write(
                resources.join("app/app.R"),
                b"shiny::shinyApp(ui, server)\n",
            )?;
            fs::write(resources.join("launcher.R"), VALID_LAUNCHER)?;
            for package in ["jsonlite", "later", "shiny"] {
                let directory = resources.join("R/library").join(package);
                fs::create_dir(&directory)?;
                fs::write(
                    directory.join("DESCRIPTION"),
                    format!("Package: {package}\nVersion: 1.0.0\n"),
                )?;
            }
            let fixture = Self {
                _temporary: temporary,
                bundle,
            };
            fixture.write_manifest(&valid_manifest())?;
            Ok(fixture)
        }

        fn write_manifest(&self, manifest: &Value) -> Result<(), Box<dyn std::error::Error>> {
            fs::write(
                self.bundle.join("resources/rpackit.json"),
                serde_json::to_vec_pretty(manifest)?,
            )?;
            Ok(())
        }

        fn launcher(&self) -> PathBuf {
            self.bundle.join("resources/launcher.R")
        }
    }

    #[test]
    fn loads_current_protocol_two_bundle_without_execution()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let bundle = ValidatedBundle::load(&fixture.bundle)?;

        assert_eq!(bundle.app_type(), AppType::SingleFile);
        assert_eq!(bundle.runtime_source(), RuntimeSource::Registry);
        assert_eq!(bundle.runtime_version(), Some("4.6.1"));
        assert_eq!(bundle.packages(), ["jsonlite", "later", "shiny"]);
        assert_eq!(bundle.created_by_version(), "0.1.0");
        assert_eq!(
            bundle.rscript().file_name().and_then(|name| name.to_str()),
            Some("Rscript.exe")
        );
        assert!(bundle.bundle().is_absolute());
        assert!(bundle.resources().starts_with(bundle.bundle()));
        assert!(bundle.manifest().starts_with(bundle.resources()));
        assert!(bundle.library().starts_with(bundle.resources()));
        assert!(bundle.app().starts_with(bundle.resources()));
        assert!(bundle.launcher().starts_with(bundle.resources()));
        Ok(())
    }

    #[test]
    fn rejects_unknown_fields_and_contract_downgrades() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut unknown = valid_manifest();
        unknown["unexpected"] = json!(true);
        fixture.write_manifest(&unknown)?;
        assert!(matches!(
            ValidatedBundle::load(&fixture.bundle),
            Err(BundleError::InvalidManifestJson)
        ));

        let mutations: [(&[&str], Value); 7] = [
            (&["schema_version"], json!("2")),
            (&["launcher", "protocol_version"], json!("1")),
            (&["launcher", "token"], json!("required-argument")),
            (&["launcher", "network_token_enforced"], json!(false)),
            (&["launcher", "authentication", "token_in_url"], json!(true)),
            (
                &["launcher", "authentication", "scope"],
                json!(["websocket", "http"]),
            ),
            (
                &["launcher", "readiness", "starting_event"],
                json!("starting"),
            ),
        ];
        for (path, replacement) in mutations {
            let mut manifest = valid_manifest();
            replace_json_path(&mut manifest, path, replacement)?;
            fixture.write_manifest(&manifest)?;
            assert!(ValidatedBundle::load(&fixture.bundle).is_err());
        }
        Ok(())
    }

    #[test]
    fn rejects_unsafe_manifest_paths_and_runtime_substitution()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        for path in [
            "../outside/Rscript.exe",
            "R\\bin\\Rscript.exe",
            "C:/Windows/System32/cmd.exe",
            "R/bin/../Rscript.exe",
        ] {
            let mut manifest = valid_manifest();
            manifest["runtime"]["rscript"] = json!(path);
            fixture.write_manifest(&manifest)?;
            assert!(matches!(
                ValidatedBundle::load(&fixture.bundle),
                Err(BundleError::UnsupportedRuntimeContract | BundleError::UnsafeManifestPath(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn rejects_incomplete_or_ambiguous_dependencies() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut incomplete = valid_manifest();
        incomplete["dependencies"]["installed"] = json!(false);
        fixture.write_manifest(&incomplete)?;
        assert!(matches!(
            ValidatedBundle::load(&fixture.bundle),
            Err(BundleError::IncompleteDependencies)
        ));

        let mut duplicate = valid_manifest();
        duplicate["dependencies"]["packages"] = json!(["jsonlite", "later", "shiny", "shiny"]);
        fixture.write_manifest(&duplicate)?;
        assert!(matches!(
            ValidatedBundle::load(&fixture.bundle),
            Err(BundleError::InvalidDependencies)
        ));

        let mut unverified = valid_manifest();
        unverified["dependencies"]["constraints_verified"] = json!(false);
        fixture.write_manifest(&unverified)?;
        assert!(matches!(
            ValidatedBundle::load(&fixture.bundle),
            Err(BundleError::IncompleteDependencies)
        ));
        Ok(())
    }

    #[test]
    fn accepts_local_registry_provenance_but_rejects_unsafe_urls()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut local = valid_manifest();
        local["runtime"]["provenance"]["registry"] = json!("C:/runtime/versions.json");
        local["runtime"]["provenance"]["metadata_source"] =
            json!("C:/runtime/metadata/windows.json");
        local["runtime"]["provenance"]["artifact_url"] = json!("C:/runtime/artifacts/runtime.zip");
        local["dependencies"]["packages"] = json!(["shiny", "jsonlite", "later"]);
        fixture.write_manifest(&local)?;
        assert!(ValidatedBundle::load(&fixture.bundle).is_ok());

        for unsafe_reference in [
            "http://example.invalid/runtime.zip",
            "https://example.invalid/runtime.zip?token=leak",
            r"\\server\share\runtime.zip",
        ] {
            let mut manifest = valid_manifest();
            manifest["runtime"]["provenance"]["artifact_url"] = json!(unsafe_reference);
            fixture.write_manifest(&manifest)?;
            assert!(matches!(
                ValidatedBundle::load(&fixture.bundle),
                Err(BundleError::InvalidRuntimeProvenance)
            ));
        }
        Ok(())
    }

    #[test]
    fn rejects_missing_installed_package_evidence() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        fs::remove_file(fixture.bundle.join("resources/R/library/shiny/DESCRIPTION"))?;
        assert!(matches!(
            ValidatedBundle::load(&fixture.bundle),
            Err(BundleError::FileSystem { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_launcher_marker_removal_and_forbidden_transport()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        fs::write(
            fixture.launcher(),
            VALID_LAUNCHER.replace("unlink(token_file, force = TRUE)", ""),
        )?;
        assert!(matches!(
            ValidatedBundle::load(&fixture.bundle),
            Err(BundleError::LauncherContractMismatch)
        ));

        fs::write(
            fixture.launcher(),
            format!("{VALID_LAUNCHER}\nSys.setenv(RPACKIT_SESSION_TOKEN = token)\n"),
        )?;
        assert!(matches!(
            ValidatedBundle::load(&fixture.bundle),
            Err(BundleError::LauncherContractMismatch)
        ));
        Ok(())
    }

    #[test]
    fn rejects_manifest_app_layout_disagreement() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut manifest = valid_manifest();
        manifest["app"]["type"] = json!("shiny-split");
        fixture.write_manifest(&manifest)?;
        assert!(matches!(
            ValidatedBundle::load(&fixture.bundle),
            Err(BundleError::ApplicationLayoutMismatch | BundleError::FileSystem { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_oversized_manifest_and_launcher() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        fs::write(
            fixture.bundle.join("resources/rpackit.json"),
            vec![b' '; 256 * 1024 + 1],
        )?;
        assert!(matches!(
            ValidatedBundle::load(&fixture.bundle),
            Err(BundleError::ResourceTooLarge("read resource manifest"))
        ));

        fixture.write_manifest(&valid_manifest())?;
        fs::write(fixture.launcher(), vec![b'x'; 256 * 1024 + 1])?;
        assert!(matches!(
            ValidatedBundle::load(&fixture.bundle),
            Err(BundleError::ResourceTooLarge("read launcher"))
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_critical_resources() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new()?;
        let launcher = fixture.launcher();
        let real = fixture.bundle.join("real-launcher.R");
        fs::rename(&launcher, &real)?;
        symlink(real, launcher)?;
        assert!(matches!(
            ValidatedBundle::load(&fixture.bundle),
            Err(BundleError::ReparsePoint("launcher.script"))
        ));
        Ok(())
    }

    fn valid_manifest() -> Value {
        json!({
            "schema_version": "1",
            "bundle_type": "rpackit-desktop-resources",
            "app": {
                "name": "Hello",
                "type": "shiny-single-file",
                "path": "app"
            },
            "runtime": {
                "path": "R",
                "rscript": "R/bin/Rscript.exe",
                "library": "R/library",
                "platform": "windows",
                "r_version": "4.6.1",
                "source": "registry",
                "provenance": {
                    "registry": "https://github.com/rpackit/runtime/raw/main/versions.json",
                    "metadata_source": "https://github.com/rpackit/runtime/raw/main/metadata/windows-x86_64-4.6.1.json",
                    "artifact_url": "https://github.com/rpackit/runtime-win/releases/download/v4.6.1/portable-r-windows-x86_64-4.6.1.zip",
                    "sha256": "d106a4ad618a5279d9db4a61412505a5353c94e402920c0d3a627d37c5f1bf50",
                    "archive_format": "zip",
                    "cache_hit": true
                }
            },
            "launcher": {
                "script": "launcher.R",
                "host": "127.0.0.1",
                "port": "required-argument",
                "token": "private-file",
                "control": "optional-argument",
                "protocol_version": "2",
                "event_stream": {
                    "format": "ndjson",
                    "destination": "stdout",
                    "prefix": "RPACKIT_EVENT "
                },
                "network_token_enforced": true,
                "authentication": {
                    "scheme": "shiny-shared-secret",
                    "header": "Shiny-Shared-Secret",
                    "scope": ["http", "websocket"],
                    "token_transport": "private-file",
                    "token_in_url": false,
                    "minimum_shiny_version": "1.3.0"
                },
                "readiness": {
                    "strategy": "authenticated-http-poll",
                    "starting_event": "listening"
                }
            },
            "dependencies": {
                "installed": true,
                "strategy": "install-packages",
                "packages": ["jsonlite", "later", "shiny"],
                "locked_r_version": null,
                "r_constraint": null,
                "constraints": [],
                "constraints_verified": true
            },
            "created_by": {
                "package": "rpackit",
                "version": "0.1.0"
            }
        })
    }

    fn replace_json_path(
        value: &mut Value,
        path: &[&str],
        replacement: Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some((leaf, parents)) = path.split_last() else {
            return Err("JSON path must not be empty".into());
        };
        let mut current = value;
        for parent in parents {
            current = current
                .get_mut(*parent)
                .ok_or("JSON parent path was missing")?;
        }
        let object = current
            .as_object_mut()
            .ok_or("JSON parent was not an object")?;
        object.insert((*leaf).to_owned(), replacement);
        Ok(())
    }

    #[test]
    fn safe_paths_are_absolute_in_fixture() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        assert!(Path::new(&fixture.bundle).is_absolute());
        Ok(())
    }
}
