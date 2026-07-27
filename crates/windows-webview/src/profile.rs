use std::{
    fmt, fs, io,
    os::windows::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::WebviewError;

const PROFILE_PREFIX: &str = "rpackit-webview-";
const REPARSE_POINT_ATTRIBUTE: u32 = 0x400;

pub(crate) struct ScopedProfile {
    parent: PathBuf,
    path: Option<PathBuf>,
}

impl fmt::Debug for ScopedProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedProfile")
            .field("parent", &"[PRIVATE]")
            .field("path", &self.path.as_ref().map(|_| "[PRIVATE]"))
            .finish()
    }
}

impl ScopedProfile {
    pub(crate) fn create(parent: &Path) -> Result<Self, WebviewError> {
        let parent =
            fs::canonicalize(parent).map_err(|_| WebviewError::ProfileParentUnavailable)?;
        let metadata =
            fs::symlink_metadata(&parent).map_err(|_| WebviewError::ProfileParentUnavailable)?;
        if !metadata.is_dir() || is_reparse_point(&metadata) {
            return Err(WebviewError::UnsafeProfileParent);
        }
        let path = tempfile::Builder::new()
            .prefix(PROFILE_PREFIX)
            .tempdir_in(&parent)
            .map_err(|_| WebviewError::ProfileCreation)?
            .keep();
        if !profile_path_is_allowed(&parent, &path) {
            let _ = fs::remove_dir_all(&path);
            return Err(WebviewError::UnsafeProfilePath);
        }
        Ok(Self {
            parent,
            path: Some(path),
        })
    }

    pub(crate) fn path(&self) -> Result<&Path, WebviewError> {
        self.path.as_deref().ok_or(WebviewError::OwnerNotRunning)
    }

    pub(crate) fn is_removed(&self) -> bool {
        self.path.is_none()
    }

    pub(crate) async fn remove_bounded(
        &mut self,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<(), WebviewError> {
        let Some(path) = self.path.clone() else {
            return Ok(());
        };
        let deadline = Instant::now() + timeout;
        loop {
            let attempt_path = path.clone();
            let attempt_parent = self.parent.clone();
            let attempt = tokio::task::spawn_blocking(move || {
                remove_profile_once(&attempt_parent, &attempt_path)
            })
            .await
            .map_err(|_| WebviewError::ProfileCleanupWorker)?;
            match attempt {
                Ok(()) => {
                    self.path = None;
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    return Err(WebviewError::UnsafeProfilePath);
                }
                Err(_) if Instant::now() >= deadline => {
                    return Err(WebviewError::ProfileCleanup);
                }
                Err(_) => tokio::time::sleep(poll_interval).await,
            }
        }
    }

    fn remove_now(&mut self) {
        let Some(path) = self.path.clone() else {
            return;
        };
        if remove_profile_once(&self.parent, &path).is_ok() {
            self.path = None;
        }
    }
}

impl Drop for ScopedProfile {
    fn drop(&mut self) {
        self.remove_now();
    }
}

fn remove_profile_once(parent: &Path, path: &Path) -> io::Result<()> {
    if !path.try_exists()? {
        return Ok(());
    }
    if !profile_path_is_allowed(parent, path) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "profile path failed its exact-scope check",
        ));
    }
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn profile_path_is_allowed(parent: &Path, path: &Path) -> bool {
    if path.parent() != Some(parent) {
        return false;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if !name.starts_with(PROFILE_PREFIX)
        || name.len() <= PROFILE_PREFIX.len()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return false;
    }
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    metadata.is_dir() && !is_reparse_point(&metadata)
}

fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE != 0
}

#[cfg(test)]
mod tests {
    use super::{ScopedProfile, profile_path_is_allowed};

    #[tokio::test]
    async fn exact_random_profile_is_removed_without_touching_its_parent()
    -> Result<(), Box<dyn std::error::Error>> {
        let parent = tempfile::tempdir()?;
        let marker = parent.path().join("keep.txt");
        std::fs::write(&marker, b"keep")?;
        let mut profile = ScopedProfile::create(parent.path())?;
        let profile_path = profile.path()?.to_path_buf();
        assert!(profile_path_is_allowed(
            &std::fs::canonicalize(parent.path())?,
            &profile_path
        ));
        std::fs::create_dir(profile_path.join("nested"))?;
        std::fs::write(profile_path.join("nested").join("state"), b"state")?;

        profile
            .remove_bounded(
                std::time::Duration::from_secs(2),
                std::time::Duration::from_millis(10),
            )
            .await?;

        assert!(profile.is_removed());
        assert!(marker.is_file());
        Ok(())
    }
}
