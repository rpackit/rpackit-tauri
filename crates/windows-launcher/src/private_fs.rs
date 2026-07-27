//! Native, atomically restricted Windows launch-session files.

use std::ffi::{OsStr, c_void};
use std::fs::{self, File};
use std::io::Write;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::OwnedHandle;
use std::path::{Component, Path, PathBuf};

use windows::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_INSUFFICIENT_BUFFER, HLOCAL, LocalFree, NO_ERROR,
};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE,
    FILE_SHARE_NONE,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{HRESULT, PCWSTR, PWSTR};
use zeroize::Zeroizing;

use super::{LaunchError, api_error, native_structure_size, owned_handle};

const SESSION_PREFIX: &str = "rpackit-session-";
const SESSION_RANDOM_BYTES: usize = 16;
const SESSION_CREATE_ATTEMPTS: usize = 8;
const TOKEN_MIN_BYTES: usize = 16;
const TOKEN_MAX_BYTES: usize = 256;
const TOKEN_LEAF: &str = "token";
const CONTROL_LEAF: &str = "control";

/// One atomically restricted Windows launch directory.
///
/// The directory and each created file have a protected DACL with exactly two
/// full-control allow entries: the current account and `SYSTEM`. The token
/// value is stored only in the token file and is never retained by this value.
///
/// Cleanup is intentionally explicit. Call [`PrivateSession::cleanup`] only
/// after the launch Job and every member process have stopped.
#[derive(Debug)]
#[must_use = "the private session must be cleaned after the launch Job stops"]
pub struct PrivateSession {
    directory: PathBuf,
    token_path: PathBuf,
    control_path: PathBuf,
    directory_sddl: String,
    file_sddl: String,
}

impl PrivateSession {
    /// Creates a random empty private directory.
    ///
    /// The parent must already exist and be an absolute path without `.` or
    /// `..` components. Both fixed file paths remain absent so the caller can
    /// generate launch secrets and bind listeners after this DACL gate.
    ///
    /// # Errors
    ///
    /// Returns an error before creating anything for an invalid parent.
    /// Native creation, DACL readback, and randomness failures also fail
    /// closed and trigger best-effort rollback of only the exact path allocated
    /// by this call.
    pub fn create(parent: impl AsRef<Path>) -> Result<Self, LaunchError> {
        let parent = parent.as_ref();
        validate_parent(parent)?;

        let account_sid = current_account_sid()?;
        let directory_sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{account_sid})");
        let file_sddl = format!("D:P(A;;FA;;;SY)(A;;FA;;;{account_sid})");
        let directory = create_random_directory(parent, &directory_sddl)?;
        let token_path = private_child_path(&directory, TOKEN_LEAF)?;
        let control_path = private_child_path(&directory, CONTROL_LEAF)?;
        let session = Self {
            directory,
            token_path,
            control_path,
            directory_sddl,
            file_sddl,
        };

        if let Err(error) = session.verify_security() {
            session.rollback_known_paths();
            return Err(error);
        }

        Ok(session)
    }

    /// Atomically creates the protected one-time token file.
    ///
    /// The token must contain 16-256 URL-safe ASCII characters. The file
    /// contains exactly the token followed by one LF. Its temporary native
    /// write buffer is zeroized after the file closes.
    ///
    /// # Errors
    ///
    /// Returns an error before creating the file for an invalid token. An
    /// existing fixed token path, native creation failure, write failure, or
    /// DACL mismatch also fails closed without removing the reusable session
    /// directory.
    pub fn write_token_file(&self, token: &str) -> Result<(), LaunchError> {
        validate_token(token)?;
        let mut payload = Zeroizing::new(Vec::with_capacity(token.len() + 1));
        payload.extend_from_slice(token.as_bytes());
        payload.push(b'\n');
        create_private_file(&self.token_path, TOKEN_LEAF, &payload, &self.file_sddl)
    }

    /// Returns the private launch directory.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Returns the token-file path to pass to the launcher.
    ///
    /// The path itself is not secret; the file contents are.
    #[must_use]
    pub fn token_path(&self) -> &Path {
        &self.token_path
    }

    /// Returns the graceful-shutdown control-file path.
    #[must_use]
    pub fn control_path(&self) -> &Path {
        &self.control_path
    }

    /// Atomically creates the empty, protected graceful-shutdown control file.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed control path already exists, native file
    /// creation fails, or DACL readback does not exactly match the required
    /// descriptor.
    pub fn create_control_file(&self) -> Result<(), LaunchError> {
        create_private_file(&self.control_path, CONTROL_LEAF, &[], &self.file_sddl)
    }

    /// Re-verifies the exact protected DACL on the session and known files.
    ///
    /// A token deleted by the R launcher and a not-yet-created control file are
    /// both valid states. Any known file that does exist must match.
    ///
    /// # Errors
    ///
    /// Returns an error when an existing path cannot be inspected or its DACL
    /// differs from the descriptor applied at creation.
    pub fn verify_security(&self) -> Result<(), LaunchError> {
        verify_exact_dacl(&self.directory, &self.directory_sddl)?;
        if path_exists(&self.token_path)? {
            verify_exact_dacl(&self.token_path, &self.file_sddl)?;
        }
        if path_exists(&self.control_path)? {
            verify_exact_dacl(&self.control_path, &self.file_sddl)?;
        }
        Ok(())
    }

    /// Removes only the two known files and then the now-empty session folder.
    ///
    /// No recursive deletion is performed. An unexpected entry makes the
    /// final directory removal fail closed, preserving that entry for audit.
    /// Call this only after the owned launch Job has stopped.
    ///
    /// # Errors
    ///
    /// Returns an error when Windows cannot remove a known file or the exact
    /// session directory.
    pub fn cleanup(&self) -> Result<(), LaunchError> {
        remove_file_if_present(&self.token_path)?;
        remove_file_if_present(&self.control_path)?;
        match fs::remove_dir(&self.directory) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(LaunchError::FileSystem {
                operation: "remove private-session directory",
                source,
            }),
        }
    }

    fn rollback_known_paths(&self) {
        let _ = fs::remove_file(&self.token_path);
        let _ = fs::remove_file(&self.control_path);
        let _ = fs::remove_dir(&self.directory);
    }
}

fn validate_parent(parent: &Path) -> Result<(), LaunchError> {
    let normalized = parent
        .components()
        .all(|component| !matches!(component, Component::CurDir | Component::ParentDir));
    if !parent.is_absolute() || !parent.is_dir() || !normalized {
        return Err(LaunchError::InvalidSessionParent);
    }
    Ok(())
}

fn validate_token(token: &str) -> Result<(), LaunchError> {
    let valid_length = (TOKEN_MIN_BYTES..=TOKEN_MAX_BYTES).contains(&token.len());
    let valid_alphabet = token
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-'));
    if !valid_length || !valid_alphabet {
        return Err(LaunchError::InvalidToken);
    }
    Ok(())
}

fn private_child_path(directory: &Path, leaf: &str) -> Result<PathBuf, LaunchError> {
    let mut components = Path::new(leaf).components();
    let valid = matches!(components.next(), Some(Component::Normal(_)))
        && components.next().is_none()
        && !leaf.is_empty();
    if !valid {
        return Err(LaunchError::InvalidPrivateLeaf);
    }
    Ok(directory.join(leaf))
}

fn create_random_directory(parent: &Path, sddl: &str) -> Result<PathBuf, LaunchError> {
    let descriptor = LocalSecurityDescriptor::from_sddl(sddl)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: native_structure_size::<SECURITY_ATTRIBUTES>()?,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: false.into(),
    };

    for _ in 0..SESSION_CREATE_ATTEMPTS {
        let mut random = [0_u8; SESSION_RANDOM_BYTES];
        getrandom::fill(&mut random).map_err(|_| LaunchError::RandomGenerationFailed)?;
        let directory = parent.join(format!("{SESSION_PREFIX}{}", hex::encode(random)));
        let wide = nul_terminated_path(&directory)?;
        // SAFETY: The path and security descriptor are valid and remain live
        // through the call. The protected DACL is therefore applied atomically
        // when Windows creates the directory.
        match unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(&raw const attributes)) } {
            Ok(()) => {
                if let Err(error) = verify_exact_dacl(&directory, sddl) {
                    let _ = fs::remove_dir(&directory);
                    return Err(error);
                }
                return Ok(directory);
            }
            Err(error) if is_exists_error(&error) => {}
            Err(error) => return Err(api_error("CreateDirectoryW", &error)),
        }
    }
    Err(LaunchError::SessionNameCollisions)
}

fn create_private_file(
    path: &Path,
    label: &'static str,
    contents: &[u8],
    sddl: &str,
) -> Result<(), LaunchError> {
    let descriptor = LocalSecurityDescriptor::from_sddl(sddl)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: native_structure_size::<SECURITY_ATTRIBUTES>()?,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: false.into(),
    };
    let wide = nul_terminated_path(path)?;
    // SAFETY: The path and descriptor remain live through the call. CREATE_NEW
    // prevents replacement, and the protected DACL is applied atomically.
    let raw_file = match unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            Some(&raw const attributes),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    } {
        Ok(handle) => handle,
        Err(error) if is_exists_error(&error) => {
            return Err(LaunchError::PrivateFileAlreadyExists(label));
        }
        Err(error) => return Err(api_error("CreateFileW", &error)),
    };
    // SAFETY: CreateFileW returned one new owned handle, transferred once.
    let handle: OwnedHandle = unsafe { owned_handle(raw_file) };
    let mut file = File::from(handle);
    if let Err(source) = file.write_all(contents).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(LaunchError::FileSystem {
            operation: "write private-session file",
            source,
        });
    }
    drop(file);

    if let Err(error) = verify_exact_dacl(path, sddl) {
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

fn current_account_sid() -> Result<String, LaunchError> {
    let mut raw_token = windows::Win32::Foundation::HANDLE::default();
    // SAFETY: GetCurrentProcess returns the caller pseudo-handle. The output
    // pointer receives one new token handle on success.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw_token) }
        .map_err(|error| api_error("OpenProcessToken", &error))?;
    // SAFETY: OpenProcessToken returned one new owned handle, transferred once.
    let token = unsafe { owned_handle(raw_token) };

    let mut required_bytes = 0_u32;
    // SAFETY: This is the documented sizing call. It writes only the required
    // byte count because the information pointer and length are empty.
    let sizing = unsafe {
        GetTokenInformation(
            super::raw_handle(&token),
            TokenUser,
            None,
            0,
            &raw mut required_bytes,
        )
    };
    if let Err(error) = sizing
        && error.code() != HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0)
    {
        return Err(api_error("GetTokenInformation(size)", &error));
    }
    if usize::try_from(required_bytes).map_or(true, |bytes| bytes < size_of::<TOKEN_USER>()) {
        return Err(LaunchError::MalformedTokenInformation);
    }

    let required =
        usize::try_from(required_bytes).map_err(|_| LaunchError::MalformedTokenInformation)?;
    let words = required.div_ceil(size_of::<usize>());
    let mut information = vec![0_usize; words];
    let mut returned_bytes = required_bytes;
    // SAFETY: The aligned buffer is writable for at least `required_bytes`,
    // and the returned length pointer remains valid for the call.
    unsafe {
        GetTokenInformation(
            super::raw_handle(&token),
            TokenUser,
            Some(information.as_mut_ptr().cast()),
            required_bytes,
            &raw mut returned_bytes,
        )
    }
    .map_err(|error| api_error("GetTokenInformation", &error))?;
    if returned_bytes
        < u32::try_from(size_of::<TOKEN_USER>())
            .map_err(|_| LaunchError::MalformedTokenInformation)?
        || returned_bytes > required_bytes
    {
        return Err(LaunchError::MalformedTokenInformation);
    }

    // SAFETY: GetTokenInformation initialized at least one TOKEN_USER in the
    // aligned buffer, and the size checks above cover that structure.
    let token_user = unsafe { &*information.as_ptr().cast::<TOKEN_USER>() };
    if token_user.User.Sid.is_invalid() {
        return Err(LaunchError::MalformedTokenInformation);
    }
    let mut sid_string = PWSTR::null();
    // SAFETY: The SID points into the live token-information buffer and the
    // output receives one LocalAlloc-backed string on success.
    unsafe { ConvertSidToStringSidW(token_user.User.Sid, &raw mut sid_string) }
        .map_err(|error| api_error("ConvertSidToStringSidW", &error))?;
    let sid_string = LocalWideString::new(sid_string)?;
    sid_string.to_string()
}

fn verify_exact_dacl(path: &Path, expected_sddl: &str) -> Result<(), LaunchError> {
    let expected = LocalSecurityDescriptor::from_sddl(expected_sddl)?;
    let expected = expected.dacl_sddl()?;
    let path_wide = nul_terminated_path(path)?;
    let mut actual = PSECURITY_DESCRIPTOR::default();
    // SAFETY: The path remains live and the output pointer receives one
    // LocalAlloc-backed security descriptor on success.
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(path_wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &raw mut actual,
        )
    };
    if status != NO_ERROR {
        if !actual.is_invalid() {
            drop(LocalSecurityDescriptor(actual));
        }
        return Err(LaunchError::WindowsApi {
            operation: "GetNamedSecurityInfoW",
            code: HRESULT::from_win32(status.0).0.cast_unsigned(),
        });
    }
    let actual = LocalSecurityDescriptor::new(actual)?;
    if actual.dacl_sddl()? != expected {
        return Err(LaunchError::PrivateDaclMismatch);
    }
    Ok(())
}

fn remove_file_if_present(path: &Path) -> Result<(), LaunchError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(LaunchError::FileSystem {
            operation: "remove private-session file",
            source,
        }),
    }
}

fn path_exists(path: &Path) -> Result<bool, LaunchError> {
    path.try_exists().map_err(|source| LaunchError::FileSystem {
        operation: "inspect private-session path",
        source,
    })
}

fn nul_terminated_path(path: &Path) -> Result<Vec<u16>, LaunchError> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(LaunchError::InteriorNul("private-session path"));
    }
    wide.push(0);
    Ok(wide)
}

fn is_exists_error(error: &windows::core::Error) -> bool {
    error.code() == HRESULT::from_win32(ERROR_ALREADY_EXISTS.0)
        || error.code() == HRESULT::from_win32(ERROR_FILE_EXISTS.0)
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl LocalSecurityDescriptor {
    fn new(descriptor: PSECURITY_DESCRIPTOR) -> Result<Self, LaunchError> {
        if descriptor.is_invalid() {
            return Err(LaunchError::PrivateDaclMismatch);
        }
        Ok(Self(descriptor))
    }

    fn from_sddl(sddl: &str) -> Result<Self, LaunchError> {
        let wide = nul_terminated_os(OsStr::new(sddl), "security descriptor")?;
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: The input is NUL-terminated and remains live. The output
        // receives one LocalAlloc-backed descriptor on success.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
        }
        .map_err(|error| {
            api_error(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                &error,
            )
        })?;
        Self::new(descriptor)
    }

    fn as_ptr(&self) -> *mut c_void {
        self.0.0
    }

    fn dacl_sddl(&self) -> Result<String, LaunchError> {
        let mut string = PWSTR::null();
        // SAFETY: The descriptor is valid and live. The output receives one
        // LocalAlloc-backed UTF-16 string on success.
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                self.0,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &raw mut string,
                None,
            )
        }
        .map_err(|error| {
            api_error(
                "ConvertSecurityDescriptorToStringSecurityDescriptorW",
                &error,
            )
        })?;
        LocalWideString::new(string)?.to_string()
    }
}

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: Conversion/GetNamedSecurityInfo allocated this pointer with
        // LocalAlloc, and this owner frees it exactly once.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

struct LocalWideString(PWSTR);

impl LocalWideString {
    fn new(string: PWSTR) -> Result<Self, LaunchError> {
        if string.is_null() {
            return Err(LaunchError::PrivateDaclMismatch);
        }
        Ok(Self(string))
    }

    fn to_string(&self) -> Result<String, LaunchError> {
        // SAFETY: The owned conversion result is NUL-terminated and remains
        // live for this conversion.
        unsafe { PCWSTR(self.0.0).to_string() }.map_err(|_| LaunchError::MalformedSecurityString)
    }
}

impl Drop for LocalWideString {
    fn drop(&mut self) {
        // SAFETY: The conversion API allocated this string with LocalAlloc,
        // and this owner frees it exactly once.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0.cast()))) };
    }
}

fn nul_terminated_os(value: &OsStr, field: &'static str) -> Result<Vec<u16>, LaunchError> {
    let mut wide: Vec<u16> = value.encode_wide().collect();
    if wide.contains(&0) {
        return Err(LaunchError::InteriorNul(field));
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{private_child_path, validate_token};
    use crate::LaunchError;

    #[test]
    fn private_child_requires_one_normal_component() -> Result<(), LaunchError> {
        let directory = Path::new(r"C:\private");
        for leaf in ["", ".", "..", r"..\escape", r"nested\file", r"C:\absolute"] {
            assert!(matches!(
                private_child_path(directory, leaf),
                Err(LaunchError::InvalidPrivateLeaf)
            ));
        }
        assert_eq!(
            private_child_path(directory, "control")?,
            directory.join("control")
        );
        Ok(())
    }

    #[test]
    fn token_alphabet_and_bounds_are_strict() {
        assert!(validate_token("Abcdefghijklmnop").is_ok());
        assert!(validate_token(&"A".repeat(256)).is_ok());
        for token in [
            "short",
            "contains/slash___",
            "contains newline\n",
            "not-ascii-你好你好",
        ] {
            assert!(matches!(
                validate_token(token),
                Err(LaunchError::InvalidToken)
            ));
        }
        assert!(matches!(
            validate_token(&"A".repeat(257)),
            Err(LaunchError::InvalidToken)
        ));
    }
}
