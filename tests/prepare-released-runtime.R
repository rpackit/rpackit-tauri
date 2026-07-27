if (!identical(Sys.getenv("GITHUB_ACTIONS"), "true")) {
  stop(
    "The released-runtime preparation script is restricted to GitHub Actions.",
    call. = FALSE
  )
}

arguments <- commandArgs(trailingOnly = TRUE)
if (length(arguments) != 4L) {
  stop(
    paste(
      "Usage: prepare-released-runtime.R",
      "<hello-shiny> <runtime-home> <bundle-output> <evidence-output>"
    ),
    call. = FALSE
  )
}

app_path <- normalizePath(arguments[[1L]], winslash = "/", mustWork = TRUE)
runtime_path <- normalizePath(
  arguments[[2L]],
  winslash = "/",
  mustWork = TRUE
)
bundle_path <- arguments[[3L]]
evidence_path <- arguments[[4L]]
if (file.exists(bundle_path) || dir.exists(bundle_path)) {
  stop("The released-runtime bundle output already exists.", call. = FALSE)
}
if (file.exists(evidence_path) || dir.exists(evidence_path)) {
  stop("The bundle-evidence output already exists.", call. = FALSE)
}

required_environment <- function(name) {
  value <- Sys.getenv(name, unset = NA_character_)
  if (is.na(value) || !nzchar(value)) {
    stop(name, " is not configured.", call. = FALSE)
  }
  value
}

runtime_version <- required_environment("RPACKIT_RUNTIME_VERSION")
runtime_sha256 <- tolower(required_environment("RPACKIT_RUNTIME_SHA256"))
rpackit_commit <- tolower(required_environment("RPACKIT_PACKAGE_SHA"))
examples_commit <- tolower(required_environment("RPACKIT_EXAMPLES_SHA"))
cran_repository <- required_environment("RPACKIT_CRAN_REPOSITORY")

if (!grepl("^[0-9a-f]{64}$", runtime_sha256) ||
    !grepl("^[0-9a-f]{40}$", rpackit_commit) ||
    !grepl("^[0-9a-f]{40}$", examples_commit)) {
  stop("Released-runtime provenance identifiers are malformed.", call. = FALSE)
}
if (!grepl("^https://", cran_repository)) {
  stop("The released-runtime CRAN repository must use HTTPS.", call. = FALSE)
}

# Keep the already initialized system-R library available to this process,
# while preventing its paths and profiles from leaking into bundled Rscript
# probes or dependency installation.
Sys.unsetenv(c(
  "R_ARCH",
  "R_DOC_DIR",
  "R_ENVIRON",
  "R_ENVIRON_USER",
  "R_HOME",
  "R_INCLUDE_DIR",
  "R_LIBS",
  "R_LIBS_SITE",
  "R_LIBS_USER",
  "R_PROFILE",
  "R_PROFILE_USER",
  "R_SHARE_DIR"
))

bundle <- rpackit::prepare_desktop(
  app_dir = app_path,
  runtime_dir = runtime_path,
  output_dir = bundle_path,
  app_name = "hello-shiny",
  install_packages = TRUE,
  repos = c(CRAN = cran_repository),
  verify_runtime = TRUE,
  quiet = TRUE
)
validation <- rpackit::validate_desktop_bundle(
  bundle$path,
  verify_runtime = TRUE,
  quiet = TRUE
)
if (!isTRUE(validation$valid) ||
    !isTRUE(validation$dependencies_installed) ||
    !isTRUE(validation$network_token_enforced) ||
    !identical(validation$runtime_version, runtime_version) ||
    !identical(validation$app_type, "shiny-single-file")) {
  stop("The prepared release bundle failed its R-side contract.", call. = FALSE)
}

package_names <- c("jsonlite", "later", "shiny")
bundle_library <- file.path(bundle$resources, "R", "library")
package_versions <- vapply(
  package_names,
  function(package) {
    as.character(utils::packageVersion(package, lib.loc = bundle_library))
  },
  character(1)
)
manifest_path <- file.path(bundle$resources, "rpackit.json")
evidence <- list(
  schema_version = "1",
  gate = "released-portable-r-bundle-preparation",
  runtime = list(
    version = runtime_version,
    sha256 = runtime_sha256,
    source = "github-release"
  ),
  sources = list(
    rpackit_commit = rpackit_commit,
    examples_commit = examples_commit,
    rpackit_version = as.character(utils::packageVersion("rpackit"))
  ),
  bundle = list(
    app_type = validation$app_type,
    dependencies_installed = validation$dependencies_installed,
    network_token_enforced = validation$network_token_enforced,
    manifest_sha256 = digest::digest(
      manifest_path,
      algo = "sha256",
      serialize = FALSE,
      file = TRUE
    ),
    package_versions = as.list(package_versions)
  ),
  retained_artifact = FALSE
)

staging_evidence <- tempfile(
  "bundle-provenance-",
  tmpdir = dirname(evidence_path),
  fileext = ".json.tmp"
)
on.exit(unlink(staging_evidence, force = TRUE), add = TRUE)
jsonlite::write_json(
  evidence,
  staging_evidence,
  auto_unbox = TRUE,
  pretty = TRUE
)
if (!file.rename(staging_evidence, evidence_path)) {
  stop("Cannot publish bundle-preparation evidence.", call. = FALSE)
}
