//! Audited Windows process creation for the bundled rpackit R launcher.
//!
//! A launcher process is created suspended, assigned to an unnamed,
//! non-inheritable Job Object configured with kill-on-close, verified as a Job
//! member, and only then resumed. The child inherits exactly three standard-I/O
//! pipe handles; it never inherits the Job handle.
//!
//! A separate native boundary atomically creates each random launch directory
//! and token/control file with a protected DACL restricted to the current
//! account and `SYSTEM`, then reads the descriptor back exactly.

#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]

mod private_fs;

use std::cmp::Ordering;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::mem::{offset_of, size_of};
use std::net::Ipv4Addr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;
use windows::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, FILETIME, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT,
    HANDLE_FLAGS, NO_ERROR, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Globalization::{
    CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN, CompareStringOrdinal,
};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP_STATE_LISTEN, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
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
    GetProcessTimes, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};
use windows::core::{BOOL, PCWSTR, PWSTR};
use zeroize::{Zeroize, Zeroizing};

pub use private_fs::PrivateSession;

const WINDOWS_COMMAND_LINE_LIMIT: usize = 32_767;
const INTERNAL_FAILURE_EXIT_CODE: u32 = 0x5250_4B49;

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
struct EnvironmentEntry {
    name: Vec<u16>,
    value: Vec<u16>,
}

/// An explicit Unicode environment block for one launched process.
///
/// Names are unique under Windows' locale-independent, case-insensitive
/// ordinal comparison. The serialized block is kept in Windows' required sort
/// order and is zeroized after process creation. Debug output reports only the
/// number of entries, never names or values.
#[derive(Clone, Default, Zeroize)]
#[zeroize(drop)]
pub struct LaunchEnvironment {
    entries: Vec<EnvironmentEntry>,
}

impl fmt::Debug for LaunchEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaunchEnvironment")
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl LaunchEnvironment {
    /// Creates an explicit empty environment.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Copies the current process environment into a validated explicit block.
    ///
    /// Repeated Windows-equivalent names are collapsed deterministically, with
    /// the last observed value taking precedence.
    ///
    /// # Errors
    ///
    /// Returns an error if the current block contains a malformed name or
    /// value, or Windows cannot compare its names.
    pub fn from_current() -> Result<Self, LaunchError> {
        let mut environment = Self::empty();
        for (name, value) in std::env::vars_os() {
            environment.set(name, value)?;
        }
        Ok(environment)
    }

    /// Sets or replaces one variable using Windows case-insensitive identity.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty name, a name containing `=` or a NUL, a
    /// value containing a NUL, or a failed native name comparison.
    pub fn set(
        &mut self,
        name: impl AsRef<OsStr>,
        value: impl AsRef<OsStr>,
    ) -> Result<(), LaunchError> {
        let name = environment_name(name.as_ref())?;
        let value = environment_value(value.as_ref())?;
        if let Some(index) = self.find_name(&name)? {
            self.entries[index] = EnvironmentEntry { name, value };
        } else {
            self.entries.push(EnvironmentEntry { name, value });
        }
        self.sort_entries()
    }

    /// Removes one variable using Windows case-insensitive identity.
    ///
    /// Returns whether a matching entry existed.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed name or a failed native comparison.
    pub fn remove(&mut self, name: impl AsRef<OsStr>) -> Result<bool, LaunchError> {
        let name = environment_name(name.as_ref())?;
        let Some(index) = self.find_name(&name)? else {
            return Ok(false);
        };
        self.entries.remove(index);
        Ok(true)
    }

    /// Returns the number of case-insensitively unique entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether this explicit environment has no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn find_name(&self, name: &[u16]) -> Result<Option<usize>, LaunchError> {
        for (index, entry) in self.entries.iter().enumerate() {
            if compare_environment_names(&entry.name, name)? == Ordering::Equal {
                return Ok(Some(index));
            }
        }
        Ok(None)
    }

    fn sort_entries(&mut self) -> Result<(), LaunchError> {
        for index in 1..self.entries.len() {
            let mut cursor = index;
            while cursor > 0
                && compare_environment_names(
                    &self.entries[cursor - 1].name,
                    &self.entries[cursor].name,
                )? == Ordering::Greater
            {
                self.entries.swap(cursor - 1, cursor);
                cursor -= 1;
            }
        }
        Ok(())
    }

    fn encoded_block(&self) -> Result<Zeroizing<Vec<u16>>, LaunchError> {
        let capacity = self.entries.iter().try_fold(1_usize, |total, entry| {
            total
                .checked_add(entry.name.len())
                .and_then(|value| value.checked_add(1))
                .and_then(|value| value.checked_add(entry.value.len()))
                .and_then(|value| value.checked_add(1))
                .ok_or(LaunchError::EnvironmentBlockTooLarge)
        })?;
        let mut block = Zeroizing::new(Vec::with_capacity(capacity.max(2)));
        for entry in &self.entries {
            block.extend_from_slice(&entry.name);
            block.push(u16::from(b'='));
            block.extend_from_slice(&entry.value);
            block.push(0);
        }
        block.push(0);
        if self.entries.is_empty() {
            block.push(0);
        }
        Ok(block)
    }
}

/// A bundled executable invocation to be placed in an owned Windows Job.
#[derive(Clone, Debug)]
pub struct LaunchCommand {
    program: PathBuf,
    arguments: Vec<OsString>,
    current_directory: PathBuf,
    environment: Option<LaunchEnvironment>,
}

impl LaunchCommand {
    /// Creates a command with an explicit absolute executable path.
    pub fn new(program: impl Into<PathBuf>, current_directory: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            current_directory: current_directory.into(),
            environment: None,
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

    /// Uses a validated explicit Unicode environment instead of inheriting the
    /// parent's block.
    #[must_use]
    pub fn environment(mut self, environment: LaunchEnvironment) -> Self {
        self.environment = Some(environment);
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

/// A create-time-aware handle for one live process verified in the launch Job.
///
/// Holding this handle prevents the represented process identity from being
/// confused with a later reuse of the same numeric PID.
#[derive(Debug)]
pub struct JobMemberProcess {
    process: OwnedHandle,
    identity: ProcessIdentity,
}

impl JobMemberProcess {
    /// Returns the exact PID and creation time captured from the process handle.
    #[must_use]
    pub const fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    /// Returns whether the exact captured process is still running.
    ///
    /// # Errors
    ///
    /// Returns an error if Windows cannot query the process handle.
    pub fn is_alive(&self) -> Result<bool, LaunchError> {
        process_is_alive(&self.process)
    }

    /// Waits up to `timeout` for the exact captured process to exit.
    ///
    /// Returns `Ok(None)` on timeout and `Ok(Some(code))` after termination.
    ///
    /// # Errors
    ///
    /// Returns an error if the process wait or exit-code query fails.
    pub fn wait(&self, timeout: Duration) -> Result<Option<u32>, LaunchError> {
        wait_for_process(&self.process, timeout)
    }
}

/// Exact loopback listener identity verified from Windows' owner-PID tables.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerIdentity {
    /// Create-time-aware process identity held by [`JobMemberProcess`].
    pub process: ProcessIdentity,
    /// Required upstream address.
    pub address: Ipv4Addr,
    /// Required upstream port.
    pub port: u16,
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

    /// Captures a live create-time-aware handle for a reported Job member PID.
    ///
    /// The returned handle is non-inheritable and remains tied to the exact
    /// process even if Windows later reuses its numeric PID.
    ///
    /// # Errors
    ///
    /// Returns an error for PID zero, an inaccessible or exited process, a
    /// process outside this launch's Job, or a native identity query failure.
    pub fn capture_job_member(&self, pid: u32) -> Result<JobMemberProcess, LaunchError> {
        if pid == 0 {
            return Err(LaunchError::InvalidProcessId);
        }
        // SAFETY: OpenProcess validates the PID and returns one new
        // non-inheritable handle on success.
        let raw_process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                pid,
            )
        }
        .map_err(|error| api_error("OpenProcess", &error))?;
        // SAFETY: OpenProcess returned a new owned handle, transferred once.
        let process = unsafe { owned_handle(raw_process) };

        if !process_is_alive(&process)? {
            return Err(LaunchError::ProcessAlreadyExited);
        }
        let identity = process_identity(&process, pid)?;
        if !process_is_in_job(&process, &self.job)? {
            return Err(LaunchError::ProcessOutsideJob);
        }
        if !process_is_alive(&process)? {
            return Err(LaunchError::ProcessAlreadyExited);
        }

        Ok(JobMemberProcess { process, identity })
    }

    /// Verifies one exact `127.0.0.1` TCP listener owned by a captured member.
    ///
    /// The selected port must have exactly one IPv4 listener row, with the
    /// captured process PID and exact loopback address, and no IPv6 listener
    /// row. The member is checked for Job membership and liveness both around
    /// the owner-table snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for port zero, an exited or outside-Job member,
    /// malformed/unavailable Windows owner tables, a missing exact listener,
    /// or any competing listener on the selected port.
    pub fn verify_ipv4_listener(
        &self,
        member: &JobMemberProcess,
        port: u16,
    ) -> Result<ListenerIdentity, LaunchError> {
        if port == 0 {
            return Err(LaunchError::InvalidListenerPort);
        }
        if !process_is_alive(&member.process)? {
            return Err(LaunchError::ProcessAlreadyExited);
        }
        if !process_is_in_job(&member.process, &self.job)? {
            return Err(LaunchError::ProcessOutsideJob);
        }

        let ipv4 = ipv4_listener_rows()?;
        let ipv6 = ipv6_listener_rows()?;
        let pid = member.identity.pid;
        let mut exact = 0_usize;
        let mut ipv4_on_port = 0_usize;
        for row in ipv4 {
            if network_port(row.dwLocalPort) != port {
                continue;
            }
            ipv4_on_port += 1;
            if row.dwLocalAddr.to_ne_bytes() == Ipv4Addr::LOCALHOST.octets()
                && row.dwOwningPid == pid
                && row.dwState == MIB_TCP_STATE_LISTEN.0.cast_unsigned()
            {
                exact += 1;
            }
        }
        let ipv6_on_port = ipv6
            .iter()
            .filter(|row| network_port(row.dwLocalPort) == port)
            .count();

        if ipv4_on_port != exact || exact > 1 || ipv6_on_port != 0 {
            return Err(LaunchError::ConflictingListener);
        }
        if exact == 0 {
            return Err(LaunchError::ExpectedListenerNotFound);
        }
        if !process_is_in_job(&member.process, &self.job)? {
            return Err(LaunchError::ProcessOutsideJob);
        }
        if !process_is_alive(&member.process)? {
            return Err(LaunchError::ProcessAlreadyExited);
        }

        Ok(ListenerIdentity {
            process: member.identity,
            address: Ipv4Addr::LOCALHOST,
            port,
        })
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
        wait_for_process(&self.process, timeout)
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
/// stderr pipe handles. A command can supply an explicit validated environment;
/// otherwise the parent's environment is inherited unchanged. No credential
/// should ever be placed in either arguments or environment variables.
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
    let environment_block = command
        .environment
        .as_ref()
        .map(LaunchEnvironment::encoded_block)
        .transpose()?;
    let environment_pointer = environment_block
        .as_ref()
        .map(|block| block.as_ptr().cast::<std::ffi::c_void>());

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
    // paths validated above. Any explicit Unicode environment block remains
    // live and double-NUL terminated for the duration of this call.
    unsafe {
        CreateProcessW(
            PCWSTR(program.as_ptr()),
            Some(PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            true,
            creation_flags,
            environment_pointer,
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

fn ipv4_listener_rows() -> Result<Vec<MIB_TCPROW_OWNER_PID>, LaunchError> {
    let table = tcp_listener_table(u32::from(AF_INET.0))?;
    read_table_rows::<MIB_TCPROW_OWNER_PID>(&table, offset_of!(MIB_TCPTABLE_OWNER_PID, table))
}

fn ipv6_listener_rows() -> Result<Vec<MIB_TCP6ROW_OWNER_PID>, LaunchError> {
    let table = tcp_listener_table(u32::from(AF_INET6.0))?;
    read_table_rows::<MIB_TCP6ROW_OWNER_PID>(&table, offset_of!(MIB_TCP6TABLE_OWNER_PID, table))
}

fn tcp_listener_table(address_family: u32) -> Result<Vec<usize>, LaunchError> {
    let mut required_bytes = 0_u32;
    // SAFETY: The null first call is the documented size query and writes only
    // `required_bytes`.
    let initial_status = unsafe {
        GetExtendedTcpTable(
            None,
            &raw mut required_bytes,
            false,
            address_family,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    if initial_status != ERROR_INSUFFICIENT_BUFFER.0 && initial_status != NO_ERROR.0 {
        return Err(LaunchError::TcpTableQueryFailed(initial_status));
    }

    for _ in 0..4 {
        let requested = usize::try_from(required_bytes)
            .map_err(|_| LaunchError::MalformedTcpTable)?
            .max(size_of::<u32>());
        let words = requested.div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; words];
        let mut supplied_bytes = u32::try_from(std::mem::size_of_val(storage.as_slice()))
            .map_err(|_| LaunchError::MalformedTcpTable)?;
        // SAFETY: `storage` is aligned and writable for `supplied_bytes`.
        // Windows writes one owner-PID listener table or reports the new size.
        let status = unsafe {
            GetExtendedTcpTable(
                Some(storage.as_mut_ptr().cast()),
                &raw mut supplied_bytes,
                false,
                address_family,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if status == NO_ERROR.0 {
            return Ok(storage);
        }
        if status != ERROR_INSUFFICIENT_BUFFER.0 {
            return Err(LaunchError::TcpTableQueryFailed(status));
        }
        required_bytes = supplied_bytes;
    }
    Err(LaunchError::TcpTableChangedRepeatedly)
}

fn read_table_rows<T: Copy>(storage: &[usize], rows_offset: usize) -> Result<Vec<T>, LaunchError> {
    let available = std::mem::size_of_val(storage);
    if available < size_of::<u32>() || size_of::<T>() == 0 || rows_offset > available {
        return Err(LaunchError::MalformedTcpTable);
    }
    let base = storage.as_ptr().cast::<u8>();
    // SAFETY: The validated storage contains at least one u32. Unaligned read
    // avoids relying on a particular table-header packing choice.
    let count_u32 = unsafe { base.cast::<u32>().read_unaligned() };
    let count = usize::try_from(count_u32).map_err(|_| LaunchError::MalformedTcpTable)?;
    let rows_bytes = count
        .checked_mul(size_of::<T>())
        .ok_or(LaunchError::MalformedTcpTable)?;
    let end = rows_offset
        .checked_add(rows_bytes)
        .ok_or(LaunchError::MalformedTcpTable)?;
    if end > available {
        return Err(LaunchError::MalformedTcpTable);
    }

    let mut rows = Vec::with_capacity(count);
    for index in 0..count {
        let offset = rows_offset + index * size_of::<T>();
        // SAFETY: The complete row range was bounds-checked above. Rows are
        // plain Copy Win32 table records; unaligned reads tolerate SDK padding.
        rows.push(unsafe { base.add(offset).cast::<T>().read_unaligned() });
    }
    Ok(rows)
}

fn network_port(value: u32) -> u16 {
    let bytes = value.to_ne_bytes();
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn process_is_alive(process: &OwnedHandle) -> Result<bool, LaunchError> {
    // SAFETY: The process handle is owned and valid for the zero-duration
    // observation.
    let result = unsafe { WaitForSingleObject(raw_handle(process), 0) };
    if result == WAIT_TIMEOUT {
        return Ok(true);
    }
    if result == WAIT_OBJECT_0 {
        return Ok(false);
    }
    Err(LaunchError::UnexpectedWaitResult(result.0))
}

fn wait_for_process(process: &OwnedHandle, timeout: Duration) -> Result<Option<u32>, LaunchError> {
    let milliseconds = duration_milliseconds(timeout);
    // SAFETY: The process handle is owned and valid for the wait.
    let result = unsafe { WaitForSingleObject(raw_handle(process), milliseconds) };
    if result == WAIT_TIMEOUT {
        return Ok(None);
    }
    if result != WAIT_OBJECT_0 {
        return Err(LaunchError::UnexpectedWaitResult(result.0));
    }

    let mut exit_code = 0_u32;
    // SAFETY: The process has signaled, its handle is valid, and `exit_code`
    // is writable for the duration of the call.
    unsafe { GetExitCodeProcess(raw_handle(process), &raw mut exit_code) }
        .map_err(|error| api_error("GetExitCodeProcess", &error))?;
    Ok(Some(exit_code))
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

fn environment_name(value: &OsStr) -> Result<Vec<u16>, LaunchError> {
    let wide: Vec<u16> = value.encode_wide().collect();
    if wide.is_empty()
        || wide.contains(&0)
        || wide.contains(&u16::from(b'='))
        || i32::try_from(wide.len()).is_err()
    {
        return Err(LaunchError::InvalidEnvironmentName);
    }
    Ok(wide)
}

fn environment_value(value: &OsStr) -> Result<Vec<u16>, LaunchError> {
    let wide: Vec<u16> = value.encode_wide().collect();
    if wide.contains(&0) {
        return Err(LaunchError::InvalidEnvironmentValue);
    }
    Ok(wide)
}

fn compare_environment_names(left: &[u16], right: &[u16]) -> Result<Ordering, LaunchError> {
    debug_assert!(i32::try_from(left.len()).is_ok());
    debug_assert!(i32::try_from(right.len()).is_ok());
    // SAFETY: Both slices are valid UTF-16 storage with lengths already shown
    // to fit the Win32 signed count. The API reads but does not retain them.
    let result = unsafe { CompareStringOrdinal(left, right, true) };
    if result == CSTR_LESS_THAN {
        Ok(Ordering::Less)
    } else if result == CSTR_EQUAL {
        Ok(Ordering::Equal)
    } else if result == CSTR_GREATER_THAN {
        Ok(Ordering::Greater)
    } else {
        Err(LaunchError::EnvironmentComparisonFailed)
    }
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
    /// The session parent must be an existing, normalized absolute directory.
    #[error("the private-session parent is not an existing normalized absolute directory")]
    InvalidSessionParent,
    /// A private-session child name must be one ordinary path component.
    #[error("a private-session child name was not one ordinary path component")]
    InvalidPrivateLeaf,
    /// A launcher token must be 16-256 URL-safe ASCII characters.
    #[error("the launcher token was not 16-256 URL-safe ASCII characters")]
    InvalidToken,
    /// Cryptographic randomness was unavailable for a private session name.
    #[error("cryptographic randomness was unavailable for the private session name")]
    RandomGenerationFailed,
    /// Every bounded random directory name collided with an existing entry.
    #[error("every bounded private-session directory name already existed")]
    SessionNameCollisions,
    /// A fixed private file already existed in the new session.
    #[error("the private-session {0} file already existed")]
    PrivateFileAlreadyExists(&'static str),
    /// The applied DACL did not exactly match the fail-closed descriptor.
    #[error("a private-session DACL did not match the required protected descriptor")]
    PrivateDaclMismatch,
    /// Native token information did not fit its reported buffer.
    #[error("the current-account token information had an invalid layout")]
    MalformedTokenInformation,
    /// A native security string was not valid UTF-16.
    #[error("a native security string was not valid UTF-16")]
    MalformedSecurityString,
    /// A non-native private-session filesystem operation failed.
    #[error("{operation} failed: {source}")]
    FileSystem {
        /// Filesystem operation that failed.
        operation: &'static str,
        /// Underlying operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Windows command-line fields cannot contain a UTF-16 NUL.
    #[error("{0} contains an interior NUL")]
    InteriorNul(&'static str),
    /// `CreateProcessW` has a fixed command-line limit.
    #[error("the Windows command line exceeds 32,766 UTF-16 code units")]
    CommandLineTooLong,
    /// Environment names must be nonempty and contain neither `=` nor NUL.
    #[error("an environment variable name was empty or contained '=' or NUL")]
    InvalidEnvironmentName,
    /// Environment values cannot contain a UTF-16 NUL.
    #[error("an environment variable value contained a NUL")]
    InvalidEnvironmentValue,
    /// A serialized environment block overflowed addressable storage.
    #[error("the explicit environment block was too large")]
    EnvironmentBlockTooLarge,
    /// Windows could not compare two environment variable names.
    #[error("Windows could not compare environment variable names")]
    EnvironmentComparisonFailed,
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
    /// A reported process identifier cannot be zero.
    #[error("the reported process identifier was zero")]
    InvalidProcessId,
    /// The reported process had already exited during identity capture.
    #[error("the reported process exited before identity capture completed")]
    ProcessAlreadyExited,
    /// The reported process did not belong to this launch's Job.
    #[error("the reported process was outside the owned Job")]
    ProcessOutsideJob,
    /// A selected listener port cannot be zero.
    #[error("the expected listener port was zero")]
    InvalidListenerPort,
    /// Windows could not return one owner-PID TCP listener table.
    #[error("GetExtendedTcpTable failed with Win32 status {0}")]
    TcpTableQueryFailed(u32),
    /// The TCP listener table changed through every bounded sizing retry.
    #[error("the TCP listener table changed during every bounded query")]
    TcpTableChangedRepeatedly,
    /// A Windows owner-PID TCP table did not fit its reported buffer.
    #[error("the TCP listener table had an invalid layout")]
    MalformedTcpTable,
    /// No exact loopback listener was owned by the captured runtime.
    #[error("the expected runtime loopback listener was not found")]
    ExpectedListenerNotFound,
    /// Another IPv4 or IPv6 listener shared the selected upstream port.
    #[error("a conflicting listener shared the expected runtime port")]
    ConflictingListener,
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
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    use tempfile::tempdir;

    use super::{
        AssignmentTarget, LaunchCommand, LaunchEnvironment, LaunchError, build_command_line,
        launch_with_assignment_target, quote_windows_argument,
    };

    #[test]
    fn environment_is_sorted_deduplicated_and_double_terminated() -> Result<(), super::LaunchError>
    {
        let mut environment = LaunchEnvironment::empty();
        environment.set("zeta", "last")?;
        environment.set("ALPHA", "old")?;
        environment.set("beta", "middle")?;
        environment.set("alpha", "new")?;

        assert_eq!(environment.len(), 3);
        let block = environment.encoded_block()?;
        assert!(block.ends_with(&[0, 0]));
        assert!(!block.ends_with(&[0, 0, 0]));
        let entries: Vec<String> = block[..block.len() - 2]
            .split(|value| *value == 0)
            .map(String::from_utf16_lossy)
            .collect();
        assert_eq!(entries, ["alpha=new", "beta=middle", "zeta=last"]);
        Ok(())
    }

    #[test]
    fn empty_environment_has_exact_double_terminator() -> Result<(), super::LaunchError> {
        let block = LaunchEnvironment::empty().encoded_block()?;
        assert_eq!(&*block, &[0, 0]);
        Ok(())
    }

    #[test]
    fn malformed_environment_fields_are_rejected() {
        let mut environment = LaunchEnvironment::empty();
        let nul_name = OsString::from_wide(&[u16::from(b'A'), 0, u16::from(b'B')]);
        let nul_value = OsString::from_wide(&[u16::from(b'A'), 0, u16::from(b'B')]);

        assert!(matches!(
            environment.set("", "value"),
            Err(LaunchError::InvalidEnvironmentName)
        ));
        assert!(matches!(
            environment.set("A=B", "value"),
            Err(LaunchError::InvalidEnvironmentName)
        ));
        assert!(matches!(
            environment.set(nul_name, "value"),
            Err(LaunchError::InvalidEnvironmentName)
        ));
        assert!(matches!(
            environment.set("NAME", nul_value),
            Err(LaunchError::InvalidEnvironmentValue)
        ));
        assert!(matches!(
            environment.remove("="),
            Err(LaunchError::InvalidEnvironmentName)
        ));
    }

    #[test]
    fn environment_debug_never_exposes_names_or_values() -> Result<(), super::LaunchError> {
        let mut environment = LaunchEnvironment::empty();
        environment.set("SECRET_NAME", "highly-sensitive-value")?;
        let debug = format!("{environment:?}");
        assert!(debug.contains("entry_count"));
        assert!(!debug.contains("SECRET_NAME"));
        assert!(!debug.contains("highly-sensitive-value"));
        Ok(())
    }

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
