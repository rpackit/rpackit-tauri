//! Audited Windows process creation for the bundled rpackit R launcher.
//!
//! A launcher process is created suspended, assigned to an unnamed,
//! non-inheritable Job Object configured with kill-on-close, verified as a Job
//! member, and only then resumed. The child inherits exactly three standard-I/O
//! pipe handles; it never inherits the Job handle.

#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;
use windows::Win32::Foundation::{
    FILETIME, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
    GetProcessTimes, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};
use windows::core::{BOOL, PCWSTR, PWSTR};

const WINDOWS_COMMAND_LINE_LIMIT: usize = 32_767;
const INTERNAL_FAILURE_EXIT_CODE: u32 = 0x5250_4B49;

/// A bundled executable invocation to be placed in an owned Windows Job.
#[derive(Clone, Debug)]
pub struct LaunchCommand {
    program: PathBuf,
    arguments: Vec<OsString>,
    current_directory: PathBuf,
}

impl LaunchCommand {
    /// Creates a command with an explicit absolute executable path.
    pub fn new(program: impl Into<PathBuf>, current_directory: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            current_directory: current_directory.into(),
        }
    }

    /// Appends one argument without passing it through a command shell.
    #[must_use]
    pub fn arg(mut self, argument: impl Into<OsString>) -> Self {
        self.arguments.push(argument.into());
        self
    }

    /// Appends arguments without passing them through a command shell.
    #[must_use]
    pub fn args<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.arguments.extend(arguments.into_iter().map(Into::into));
        self
    }
}

/// Stable identity for the exact process created by [`launch`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    /// Windows process identifier.
    pub pid: u32,
    /// Process creation time, in 100-nanosecond intervals since 1601-01-01 UTC.
    pub creation_time_100ns: u64,
}

/// Security-relevant flags read back from the owned Job Object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobPolicy {
    /// Whether closing the last Job handle terminates all member processes.
    pub kill_on_close: bool,
    /// Whether ordinary breakaway is permitted.
    pub breakaway_allowed: bool,
    /// Whether silent breakaway is permitted.
    pub silent_breakaway_allowed: bool,
}

/// A resumed launcher process and the Job Object that owns its process tree.
///
/// Dropping this value closes the last rpackit-owned Job handle. The
/// kill-on-close policy then terminates every process still in the Job.
#[derive(Debug)]
pub struct JobProcess {
    process: OwnedHandle,
    job: OwnedHandle,
    stdout: Option<File>,
    stderr: Option<File>,
    identity: ProcessIdentity,
}

impl JobProcess {
    /// Returns the PID and creation timestamp of the exact wrapper process.
    #[must_use]
    pub const fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    /// Confirms that the exact wrapper handle remains in this launch's Job.
    ///
    /// # Errors
    ///
    /// Returns an error if Windows cannot query Job membership.
    pub fn is_in_job(&self) -> Result<bool, LaunchError> {
        let mut result = BOOL::default();
        // SAFETY: Both handles are owned and valid for this call, and `result`
        // points to initialized writable storage for the duration of the call.
        unsafe {
            IsProcessInJob(
                raw_handle(&self.process),
                Some(raw_handle(&self.job)),
                &raw mut result,
            )
        }
        .map_err(|error| api_error("IsProcessInJob", &error))?;
        Ok(result.as_bool())
    }

    /// Returns whether the Job handle is marked inheritable.
    ///
    /// A secure launch always returns `false`; this method exists so callers
    /// and lifecycle gates can independently verify the invariant.
    ///
    /// # Errors
    ///
    /// Returns an error if Windows cannot query the Job handle.
    pub fn job_handle_is_inheritable(&self) -> Result<bool, LaunchError> {
        let mut flags = 0_u32;
        // SAFETY: The Job handle is owned and valid, and `flags` is writable.
        unsafe { GetHandleInformation(raw_handle(&self.job), &raw mut flags) }
            .map_err(|error| api_error("GetHandleInformation", &error))?;
        Ok(flags & HANDLE_FLAG_INHERIT.0 != 0)
    }

    /// Reads back the security-relevant Job limit flags.
    ///
    /// A secure launch has kill-on-close enabled and both breakaway policies
    /// disabled.
    ///
    /// # Errors
    ///
    /// Returns an error if Windows cannot query the Job limits.
    pub fn job_policy(&self) -> Result<JobPolicy, LaunchError> {
        query_job_policy(&self.job)
    }

    /// Takes the read side of the child's standard-output lifecycle pipe.
    pub fn take_stdout(&mut self) -> Option<File> {
        self.stdout.take()
    }

    /// Takes the read side of the child's standard-error lifecycle pipe.
    pub fn take_stderr(&mut self) -> Option<File> {
        self.stderr.take()
    }

    /// Waits up to `timeout` for the wrapper process to exit.
    ///
    /// Returns `Ok(None)` on timeout and `Ok(Some(code))` after termination.
    ///
    /// # Errors
    ///
    /// Returns an error if the process wait or exit-code query fails.
    pub fn wait(&self, timeout: Duration) -> Result<Option<u32>, LaunchError> {
        let milliseconds = duration_milliseconds(timeout);
        // SAFETY: The process handle is owned and valid for the wait.
        let result = unsafe { WaitForSingleObject(raw_handle(&self.process), milliseconds) };
        if result == WAIT_TIMEOUT {
            return Ok(None);
        }
        if result != WAIT_OBJECT_0 {
            return Err(LaunchError::UnexpectedWaitResult(result.0));
        }

        let mut exit_code = 0_u32;
        // SAFETY: The process has signaled, its handle is valid, and
        // `exit_code` is writable for the duration of the call.
        unsafe { GetExitCodeProcess(raw_handle(&self.process), &raw mut exit_code) }
            .map_err(|error| api_error("GetExitCodeProcess", &error))?;
        Ok(Some(exit_code))
    }

    /// Terminates every process in the owned Job.
    ///
    /// # Errors
    ///
    /// Returns an error if Windows cannot terminate the Job.
    pub fn terminate(&self, exit_code: u32) -> Result<(), LaunchError> {
        // SAFETY: The Job handle is owned and valid.
        unsafe { TerminateJobObject(raw_handle(&self.job), exit_code) }
            .map_err(|error| api_error("TerminateJobObject", &error))
    }
}

/// Creates a suspended process, assigns it to a kill-on-close Job, verifies
/// membership, and resumes it.
///
/// No shell is involved. The process inherits only its stdin, stdout, and
/// stderr pipe handles. The parent's environment is inherited unchanged; no
/// credential should ever be placed there.
///
/// # Errors
///
/// Returns an error when validation or any fail-closed native launch gate
/// fails. The child is never resumed unless Job assignment and membership have
/// both succeeded.
pub fn launch(command: &LaunchCommand) -> Result<JobProcess, LaunchError> {
    launch_with_assignment_target(command, AssignmentTarget::CreatedJob)
}

#[derive(Clone, Copy)]
enum AssignmentTarget {
    CreatedJob,
    #[cfg(test)]
    InvalidHandle,
}

fn launch_with_assignment_target(
    command: &LaunchCommand,
    assignment_target: AssignmentTarget,
) -> Result<JobProcess, LaunchError> {
    validate_command(command)?;

    let job = create_kill_on_close_job()?;
    let (stdout_parent, stdout_child) = output_pipe()?;
    let (stderr_parent, stderr_child) = output_pipe()?;
    let stdin_child = closed_stdin_pipe()?;

    let inherited_handles = [
        raw_handle(&stdin_child),
        raw_handle(&stdout_child),
        raw_handle(&stderr_child),
    ];
    let attributes = AttributeList::with_handle_list(&inherited_handles)?;

    let program = nul_terminated_wide(command.program.as_os_str(), "program path")?;
    let current_directory =
        nul_terminated_wide(command.current_directory.as_os_str(), "current directory")?;
    let mut command_line = build_command_line(&command.program, &command.arguments)?;

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = native_structure_size::<STARTUPINFOEXW>()?;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = inherited_handles[0];
    startup.StartupInfo.hStdOutput = inherited_handles[1];
    startup.StartupInfo.hStdError = inherited_handles[2];
    startup.lpAttributeList = attributes.pointer;

    let mut process_information = PROCESS_INFORMATION::default();
    let creation_flags = CREATE_SUSPENDED
        | CREATE_NO_WINDOW
        | CREATE_UNICODE_ENVIRONMENT
        | EXTENDED_STARTUPINFO_PRESENT;

    // SAFETY: All pointers reference live, correctly sized storage. The
    // command-line buffer is mutable as required by CreateProcessW. The three
    // inheritable handles are explicitly allowlisted and stay alive through
    // process creation. The executable and current directory are absolute
    // paths validated above.
    unsafe {
        CreateProcessW(
            PCWSTR(program.as_ptr()),
            Some(PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            true,
            creation_flags,
            None,
            PCWSTR(current_directory.as_ptr()),
            &raw const startup.StartupInfo,
            &raw mut process_information,
        )
    }
    .map_err(|error| api_error("CreateProcessW", &error))?;

    // SAFETY: Successful CreateProcessW returns two distinct valid owned
    // handles in PROCESS_INFORMATION. Ownership transfers exactly once here.
    let process = unsafe { owned_handle(process_information.hProcess) };
    // SAFETY: See the preceding ownership argument for the primary thread.
    let thread = unsafe { owned_handle(process_information.hThread) };

    // Parent copies of child-only pipe ends must close immediately so readers
    // observe EOF when the child exits.
    drop(stdin_child);
    drop(stdout_child);
    drop(stderr_child);
    drop(attributes);

    let assignment_handle = match assignment_target {
        AssignmentTarget::CreatedJob => raw_handle(&job),
        #[cfg(test)]
        AssignmentTarget::InvalidHandle => HANDLE::default(),
    };
    // SAFETY: `process` is a live suspended process handle. The normal target
    // is a configured Job handle; the test-only invalid target exercises the
    // fail-before-resume path.
    if let Err(error) = unsafe { AssignProcessToJobObject(assignment_handle, raw_handle(&process)) }
    {
        terminate_suspended_process(&process);
        return Err(api_error("AssignProcessToJobObject", &error));
    }

    let identity = match process_identity(&process, process_information.dwProcessId) {
        Ok(identity) => identity,
        Err(error) => {
            terminate_assigned_job(&job);
            return Err(error);
        }
    };

    if !process_is_in_job(&process, &job)? {
        terminate_assigned_job(&job);
        return Err(LaunchError::JobMembershipNotEstablished);
    }

    // SAFETY: `thread` owns the still-suspended primary thread returned by
    // CreateProcessW. It has not been resumed anywhere else.
    let previous_suspend_count = unsafe { ResumeThread(raw_handle(&thread)) };
    if previous_suspend_count != 1 {
        terminate_assigned_job(&job);
        if previous_suspend_count == u32::MAX {
            return Err(last_api_error("ResumeThread"));
        }
        return Err(LaunchError::UnexpectedSuspendCount(previous_suspend_count));
    }
    drop(thread);

    Ok(JobProcess {
        process,
        job,
        stdout: Some(File::from(stdout_parent)),
        stderr: Some(File::from(stderr_parent)),
        identity,
    })
}

fn validate_command(command: &LaunchCommand) -> Result<(), LaunchError> {
    if !command.program.is_absolute() || !command.program.is_file() {
        return Err(LaunchError::InvalidProgramPath);
    }
    if !command.current_directory.is_absolute() || !command.current_directory.is_dir() {
        return Err(LaunchError::InvalidCurrentDirectory);
    }
    Ok(())
}

fn create_kill_on_close_job() -> Result<OwnedHandle, LaunchError> {
    // SAFETY: Null security attributes create a non-inheritable handle, and a
    // null name creates an unnamed Job that cannot be reopened by name.
    let raw_job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
        .map_err(|error| api_error("CreateJobObjectW", &error))?;
    // SAFETY: CreateJobObjectW returned one valid handle whose ownership is
    // transferred exactly once.
    let job = unsafe { owned_handle(raw_job) };

    let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: The Job handle is valid and `information` points to a correctly
    // sized JOBOBJECT_EXTENDED_LIMIT_INFORMATION value.
    unsafe {
        SetInformationJobObject(
            raw_handle(&job),
            JobObjectExtendedLimitInformation,
            (&raw const information).cast(),
            native_structure_size::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()?,
        )
    }
    .map_err(|error| api_error("SetInformationJobObject", &error))?;

    let mut flags = 0_u32;
    // SAFETY: The Job handle is valid and `flags` is writable.
    unsafe { GetHandleInformation(raw_handle(&job), &raw mut flags) }
        .map_err(|error| api_error("GetHandleInformation", &error))?;
    if flags & HANDLE_FLAG_INHERIT.0 != 0 {
        return Err(LaunchError::InheritableJobHandle);
    }
    let policy = query_job_policy(&job)?;
    if policy
        != (JobPolicy {
            kill_on_close: true,
            breakaway_allowed: false,
            silent_breakaway_allowed: false,
        })
    {
        return Err(LaunchError::UnexpectedJobPolicy);
    }

    Ok(job)
}

fn query_job_policy(job: &OwnedHandle) -> Result<JobPolicy, LaunchError> {
    let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    // SAFETY: The Job handle is valid and `information` points to writable,
    // correctly sized native storage.
    unsafe {
        QueryInformationJobObject(
            Some(raw_handle(job)),
            JobObjectExtendedLimitInformation,
            (&raw mut information).cast(),
            native_structure_size::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()?,
            None,
        )
    }
    .map_err(|error| api_error("QueryInformationJobObject", &error))?;
    let flags = information.BasicLimitInformation.LimitFlags;
    Ok(JobPolicy {
        kill_on_close: flags.contains(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE),
        breakaway_allowed: flags.contains(JOB_OBJECT_LIMIT_BREAKAWAY_OK),
        silent_breakaway_allowed: flags.contains(JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK),
    })
}

fn output_pipe() -> Result<(OwnedHandle, OwnedHandle), LaunchError> {
    let (read, write) = inheritable_pipe()?;
    clear_inherit_flag(&read)?;
    Ok((read, write))
}

fn closed_stdin_pipe() -> Result<OwnedHandle, LaunchError> {
    let (read, write) = inheritable_pipe()?;
    clear_inherit_flag(&write)?;
    drop(write);
    Ok(read)
}

fn inheritable_pipe() -> Result<(OwnedHandle, OwnedHandle), LaunchError> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: native_structure_size::<SECURITY_ATTRIBUTES>()?,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    // SAFETY: The output pointers and SECURITY_ATTRIBUTES remain valid for the
    // call. CreatePipe initializes both handles on success.
    unsafe {
        CreatePipe(
            &raw mut read,
            &raw mut write,
            Some(&raw const attributes),
            0,
        )
    }
    .map_err(|error| api_error("CreatePipe", &error))?;
    // SAFETY: CreatePipe returned two distinct valid handles. Each ownership
    // transfer occurs exactly once.
    let read = unsafe { owned_handle(read) };
    // SAFETY: See the preceding ownership argument for the write handle.
    let write = unsafe { owned_handle(write) };
    Ok((read, write))
}

fn clear_inherit_flag(handle: &OwnedHandle) -> Result<(), LaunchError> {
    // SAFETY: The handle is owned and valid. The mask changes only its
    // inheritance bit.
    unsafe {
        windows::Win32::Foundation::SetHandleInformation(
            raw_handle(handle),
            HANDLE_FLAG_INHERIT.0,
            HANDLE_FLAGS(0),
        )
    }
    .map_err(|error| api_error("SetHandleInformation", &error))
}

struct AttributeList {
    _storage: Vec<usize>,
    pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl AttributeList {
    fn with_handle_list(handles: &[HANDLE]) -> Result<Self, LaunchError> {
        let mut required_bytes = 0_usize;
        // SAFETY: A null first argument is the documented sizing call. Windows
        // writes only `required_bytes`; its expected insufficient-buffer error
        // is intentionally ignored after the size is checked.
        let _ =
            unsafe { InitializeProcThreadAttributeList(None, 1, None, &raw mut required_bytes) };
        if required_bytes == 0 {
            return Err(last_api_error("InitializeProcThreadAttributeList(size)"));
        }

        let words = required_bytes.div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; words];
        let pointer = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        // SAFETY: `storage` is aligned, writable, and at least the byte size
        // requested by the sizing call. It remains pinned in the Vec allocation
        // until DeleteProcThreadAttributeList runs.
        unsafe {
            InitializeProcThreadAttributeList(Some(pointer), 1, None, &raw mut required_bytes)
        }
        .map_err(|error| api_error("InitializeProcThreadAttributeList", &error))?;

        // SAFETY: `pointer` is initialized. `handles` contains valid,
        // inheritable handles and remains live through CreateProcessW.
        if let Err(error) = unsafe {
            UpdateProcThreadAttribute(
                pointer,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(handles.as_ptr().cast()),
                std::mem::size_of_val(handles),
                None,
                None,
            )
        } {
            // SAFETY: Initialization succeeded, so the list must be deleted
            // exactly once before its backing storage is freed.
            unsafe { DeleteProcThreadAttributeList(pointer) };
            return Err(api_error("UpdateProcThreadAttribute", &error));
        }

        Ok(Self {
            _storage: storage,
            pointer,
        })
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: Construction only succeeds after initialization, and Drop
        // runs exactly once while the backing storage is still alive.
        unsafe { DeleteProcThreadAttributeList(self.pointer) };
    }
}

fn process_identity(process: &OwnedHandle, pid: u32) -> Result<ProcessIdentity, LaunchError> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: The process handle is live and all FILETIME pointers are valid
    // writable storage.
    unsafe {
        GetProcessTimes(
            raw_handle(process),
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    }
    .map_err(|error| api_error("GetProcessTimes", &error))?;
    Ok(ProcessIdentity {
        pid,
        creation_time_100ns: (u64::from(creation.dwHighDateTime) << 32)
            | u64::from(creation.dwLowDateTime),
    })
}

fn process_is_in_job(process: &OwnedHandle, job: &OwnedHandle) -> Result<bool, LaunchError> {
    let mut result = BOOL::default();
    // SAFETY: Both handles are valid and `result` is writable.
    unsafe { IsProcessInJob(raw_handle(process), Some(raw_handle(job)), &raw mut result) }
        .map_err(|error| api_error("IsProcessInJob", &error))?;
    Ok(result.as_bool())
}

fn terminate_suspended_process(process: &OwnedHandle) {
    // SAFETY: The process handle is valid. Errors are intentionally ignored
    // during fail-closed cleanup; closing handles follows immediately.
    let _ = unsafe { TerminateProcess(raw_handle(process), INTERNAL_FAILURE_EXIT_CODE) };
    // SAFETY: The process handle remains valid. The bounded wait prevents this
    // cleanup path from hanging.
    let _ = unsafe { WaitForSingleObject(raw_handle(process), 5_000) };
}

fn terminate_assigned_job(job: &OwnedHandle) {
    // SAFETY: The configured Job handle is valid. Closing it also provides a
    // second kill-on-close guarantee if this explicit call reports an error.
    let _ = unsafe { TerminateJobObject(raw_handle(job), INTERNAL_FAILURE_EXIT_CODE) };
}

fn build_command_line(program: &Path, arguments: &[OsString]) -> Result<Vec<u16>, LaunchError> {
    let mut command_line = quote_windows_argument(program.as_os_str(), "program path")?;
    for (index, argument) in arguments.iter().enumerate() {
        command_line.push(u16::from(b' '));
        command_line.extend(quote_windows_argument(
            argument.as_os_str(),
            if index == 0 { "argument" } else { "arguments" },
        )?);
    }
    command_line.push(0);
    if command_line.len() > WINDOWS_COMMAND_LINE_LIMIT {
        return Err(LaunchError::CommandLineTooLong);
    }
    Ok(command_line)
}

fn quote_windows_argument(value: &OsStr, field: &'static str) -> Result<Vec<u16>, LaunchError> {
    let input: Vec<u16> = value.encode_wide().collect();
    if input.contains(&0) {
        return Err(LaunchError::InteriorNul(field));
    }

    let requires_quotes = input.is_empty()
        || input
            .iter()
            .any(|character| matches!(*character, 0x09 | 0x20 | 0x22));
    if !requires_quotes {
        return Ok(input);
    }

    let mut quoted = Vec::with_capacity(input.len() + 2);
    quoted.push(u16::from(b'"'));
    let mut backslashes = 0_usize;
    for character in input {
        if character == u16::from(b'\\') {
            backslashes += 1;
            continue;
        }
        if character == u16::from(b'"') {
            quoted.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2 + 1));
            quoted.push(character);
            backslashes = 0;
            continue;
        }
        quoted.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
        backslashes = 0;
        quoted.push(character);
    }
    quoted.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2));
    quoted.push(u16::from(b'"'));
    Ok(quoted)
}

fn nul_terminated_wide(value: &OsStr, field: &'static str) -> Result<Vec<u16>, LaunchError> {
    let mut wide: Vec<u16> = value.encode_wide().collect();
    if wide.contains(&0) {
        return Err(LaunchError::InteriorNul(field));
    }
    wide.push(0);
    Ok(wide)
}

fn duration_milliseconds(duration: Duration) -> u32 {
    u32::try_from(duration.as_millis()).unwrap_or(u32::MAX - 1)
}

fn native_structure_size<T>() -> Result<u32, LaunchError> {
    u32::try_from(size_of::<T>()).map_err(|_| LaunchError::NativeStructureTooLarge)
}

fn raw_handle(handle: &OwnedHandle) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}

unsafe fn owned_handle(handle: HANDLE) -> OwnedHandle {
    debug_assert!(!handle.is_invalid());
    // SAFETY: The caller proves this is a valid, newly owned Windows handle
    // that has not been transferred elsewhere.
    unsafe { OwnedHandle::from_raw_handle(handle.0 as RawHandle) }
}

fn api_error(operation: &'static str, error: &windows::core::Error) -> LaunchError {
    LaunchError::WindowsApi {
        operation,
        code: error.code().0.cast_unsigned(),
    }
}

fn last_api_error(operation: &'static str) -> LaunchError {
    let error = windows::core::Error::from_win32();
    api_error(operation, &error)
}

/// Fail-closed process-launch error.
#[derive(Debug, Error)]
pub enum LaunchError {
    /// The executable must be an existing file at an absolute path.
    #[error("the launcher executable is not an existing absolute file")]
    InvalidProgramPath,
    /// The working directory must be an existing absolute directory.
    #[error("the launcher working directory is not an existing absolute directory")]
    InvalidCurrentDirectory,
    /// Windows command-line fields cannot contain a UTF-16 NUL.
    #[error("{0} contains an interior NUL")]
    InteriorNul(&'static str),
    /// `CreateProcessW` has a fixed command-line limit.
    #[error("the Windows command line exceeds 32,766 UTF-16 code units")]
    CommandLineTooLong,
    /// A native structure did not fit the Windows 32-bit size field.
    #[error("a native structure is too large for its Windows size field")]
    NativeStructureTooLarge,
    /// A native operation failed with an HRESULT.
    #[error("{operation} failed with HRESULT 0x{code:08X}")]
    WindowsApi {
        /// Native operation that failed.
        operation: &'static str,
        /// HRESULT returned by the windows crate.
        code: u32,
    },
    /// The newly created process was not observed in the configured Job.
    #[error("the suspended launcher was not assigned to the owned Job")]
    JobMembershipNotEstablished,
    /// The Job handle unexpectedly allowed inheritance.
    #[error("the Job handle is inheritable")]
    InheritableJobHandle,
    /// Job limit readback did not match the fail-closed policy.
    #[error("the Job limit policy did not match kill-on-close without breakaway")]
    UnexpectedJobPolicy,
    /// `ResumeThread` did not observe the one expected suspension.
    #[error("the primary thread had unexpected suspend count {0}")]
    UnexpectedSuspendCount(u32),
    /// `WaitForSingleObject` returned neither signaled nor timeout.
    #[error("WaitForSingleObject returned unexpected status 0x{0:08X}")]
    UnexpectedWaitResult(u32),
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    use tempfile::tempdir;

    use super::{
        AssignmentTarget, LaunchCommand, build_command_line, launch_with_assignment_target,
        quote_windows_argument,
    };

    #[test]
    fn quotes_windows_arguments_without_changing_values() -> Result<(), super::LaunchError> {
        let cases = [
            (OsString::from("plain"), "plain"),
            (OsString::from(""), "\"\""),
            (OsString::from("two words"), "\"two words\""),
            (OsString::from("a\"b"), "\"a\\\"b\""),
            (OsString::from("a b\\"), "\"a b\\\\\""),
            (OsString::from("a b\\\\"), "\"a b\\\\\\\\\""),
        ];

        for (input, expected) in cases {
            let actual = quote_windows_argument(input.as_os_str(), "test")?;
            assert_eq!(String::from_utf16_lossy(&actual), expected);
        }
        Ok(())
    }

    #[test]
    fn builds_a_nul_terminated_command_line() -> Result<(), super::LaunchError> {
        let line = build_command_line(
            PathBuf::from(r"C:\Program Files\R\Rscript.exe").as_path(),
            &[
                OsString::from("--app"),
                OsString::from(r"C:\An App"),
                OsString::from("quote\"inside"),
            ],
        )?;
        assert_eq!(
            String::from_utf16_lossy(&line),
            "\"C:\\Program Files\\R\\Rscript.exe\" --app \"C:\\An App\" \"quote\\\"inside\"\0"
        );
        Ok(())
    }

    #[test]
    fn failed_job_assignment_never_resumes_the_child() -> Result<(), Box<dyn std::error::Error>> {
        let Some(system_root) = std::env::var_os("SystemRoot") else {
            return Ok(());
        };
        let command_interpreter = PathBuf::from(system_root).join("System32").join("cmd.exe");
        if !command_interpreter.is_file() {
            return Ok(());
        }
        let temporary = tempdir()?;
        let marker = temporary.path().join("executed.txt");
        let script = format!("echo executed>{}", marker.display());
        let command = LaunchCommand::new(&command_interpreter, temporary.path()).args([
            OsString::from("/D"),
            OsString::from("/Q"),
            OsString::from("/C"),
            OsString::from(script),
        ]);

        let result = launch_with_assignment_target(&command, AssignmentTarget::InvalidHandle);
        assert!(result.is_err());
        thread::sleep(Duration::from_millis(200));
        assert!(!marker.exists());
        let _ = fs::remove_file(marker);
        Ok(())
    }
}
