// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

const OUTPUT_LIMIT_EXCEEDED_MESSAGE: &str = "Process output exceeded configured limit.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutput {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Option<ProcessOutput>;

    fn run_with(
        &self,
        program: &str,
        args: &[&str],
        _cwd: Option<&Path>,
        _env: Option<&BTreeMap<OsString, OsString>>,
        _timeout: Option<Duration>,
    ) -> Option<ProcessOutput> {
        self.run(program, args)
    }

    fn run_with_output_limit(
        &self,
        program: &str,
        args: &[&str],
        cwd: Option<&Path>,
        env: Option<&BTreeMap<OsString, OsString>>,
        timeout: Option<Duration>,
        limit_bytes: usize,
    ) -> Option<ProcessOutput> {
        let output = self.run_with(program, args, cwd, env, timeout)?;
        if output.stdout.len().saturating_add(output.stderr.len()) > limit_bytes {
            return Some(output_limit_failure());
        }
        Some(output)
    }

    fn run_with_input(
        &self,
        program: &str,
        args: &[&str],
        cwd: Option<&Path>,
        env: Option<&BTreeMap<OsString, OsString>>,
        timeout: Option<Duration>,
        _input: Option<&[u8]>,
    ) -> Option<ProcessOutput> {
        self.run_with(program, args, cwd, env, timeout)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_with_input_and_fd(
        &self,
        program: &str,
        args: &[&str],
        cwd: Option<&Path>,
        env: Option<&BTreeMap<OsString, OsString>>,
        timeout: Option<Duration>,
        input: Option<&[u8]>,
        _inherited_fd: RawFd,
    ) -> Option<ProcessOutput> {
        self.run_with_input(program, args, cwd, env, timeout, input)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_with_input_and_fds(
        &self,
        _program: &str,
        _args: &[&str],
        _cwd: Option<&Path>,
        _env: Option<&BTreeMap<OsString, OsString>>,
        _timeout: Option<Duration>,
        _input: Option<&[u8]>,
        _inherited_fds: &[RawFd],
        _file_size_limit: Option<u64>,
    ) -> Option<ProcessOutput> {
        None
    }
}

#[derive(Debug, Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Option<ProcessOutput> {
        run_system(program, args, None, None, None)
    }

    fn run_with(
        &self,
        program: &str,
        args: &[&str],
        cwd: Option<&Path>,
        env: Option<&BTreeMap<OsString, OsString>>,
        timeout: Option<Duration>,
    ) -> Option<ProcessOutput> {
        run_system(program, args, cwd, env, timeout)
    }

    fn run_with_output_limit(
        &self,
        program: &str,
        args: &[&str],
        cwd: Option<&Path>,
        env: Option<&BTreeMap<OsString, OsString>>,
        timeout: Option<Duration>,
        limit_bytes: usize,
    ) -> Option<ProcessOutput> {
        run_system_with_output_limit(program, args, cwd, env, timeout, limit_bytes)
    }

    fn run_with_input(
        &self,
        program: &str,
        args: &[&str],
        cwd: Option<&Path>,
        env: Option<&BTreeMap<OsString, OsString>>,
        timeout: Option<Duration>,
        input: Option<&[u8]>,
    ) -> Option<ProcessOutput> {
        run_system_with_input(program, args, cwd, env, timeout, input, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_with_input_and_fd(
        &self,
        program: &str,
        args: &[&str],
        cwd: Option<&Path>,
        env: Option<&BTreeMap<OsString, OsString>>,
        timeout: Option<Duration>,
        input: Option<&[u8]>,
        inherited_fd: RawFd,
    ) -> Option<ProcessOutput> {
        run_system_with_input(program, args, cwd, env, timeout, input, Some(inherited_fd))
    }

    #[allow(clippy::too_many_arguments)]
    fn run_with_input_and_fds(
        &self,
        program: &str,
        args: &[&str],
        cwd: Option<&Path>,
        env: Option<&BTreeMap<OsString, OsString>>,
        timeout: Option<Duration>,
        input: Option<&[u8]>,
        inherited_fds: &[RawFd],
        file_size_limit: Option<u64>,
    ) -> Option<ProcessOutput> {
        run_system_with_input_and_fds(
            program,
            args,
            cwd,
            env,
            timeout,
            input,
            inherited_fds,
            file_size_limit,
            None,
        )
    }
}

fn run_system(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    env: Option<&BTreeMap<OsString, OsString>>,
    timeout: Option<Duration>,
) -> Option<ProcessOutput> {
    run_system_with_input(program, args, cwd, env, timeout, None, None)
}

fn run_system_with_output_limit(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    env: Option<&BTreeMap<OsString, OsString>>,
    timeout: Option<Duration>,
    limit_bytes: usize,
) -> Option<ProcessOutput> {
    run_system_with_input_and_fds(
        program,
        args,
        cwd,
        env,
        timeout,
        None,
        &[],
        None,
        Some(limit_bytes),
    )
}

fn run_system_with_input(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    env: Option<&BTreeMap<OsString, OsString>>,
    timeout: Option<Duration>,
    input: Option<&[u8]>,
    inherited_fd: Option<RawFd>,
) -> Option<ProcessOutput> {
    let inherited_fds = inherited_fd.as_slice();
    run_system_with_input_and_fds(
        program,
        args,
        cwd,
        env,
        timeout,
        input,
        inherited_fds,
        None,
        None,
    )
}

fn output_limit_failure() -> ProcessOutput {
    ProcessOutput {
        success: false,
        exit_code: Some(125),
        stdout: OUTPUT_LIMIT_EXCEEDED_MESSAGE.into(),
        stderr: String::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_system_with_input_and_fds(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    env: Option<&BTreeMap<OsString, OsString>>,
    timeout: Option<Duration>,
    input: Option<&[u8]>,
    inherited_fds: &[RawFd],
    file_size_limit: Option<u64>,
    output_limit: Option<usize>,
) -> Option<ProcessOutput> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.process_group(0);
    if !inherited_fds.is_empty() || file_size_limit.is_some() {
        let inherited_fds = inherited_fds.to_vec();
        let file_size_limit = file_size_limit
            .map(libc::rlim_t::try_from)
            .transpose()
            .ok()?;
        // SAFETY: pre_exec runs after fork and before exec. fcntl and setrlimit
        // are async-signal-safe, and every supplied descriptor remains owned
        // by the parent for the duration of this synchronous command.
        unsafe {
            command.pre_exec(move || {
                if libc::syscall(
                    libc::SYS_close_range,
                    3_u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                for fd in &inherited_fds {
                    let flags = libc::fcntl(*fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(*fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                if let Some(limit) = file_size_limit {
                    let limit = libc::rlimit {
                        rlim_cur: limit,
                        rlim_max: limit,
                    };
                    if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    if let Some(env) = env {
        command.env_clear().envs(env);
    }
    let mut child = command.spawn().ok()?;
    let mut stdin = child.stdin.take()?;
    let input = input.unwrap_or_default().to_vec();
    let stdin_writer = thread::spawn(move || stdin.write_all(&input).is_ok());
    let stdout = child.stdout.take()?;
    let stderr = child.stderr.take()?;
    let bytes_read = Arc::new(AtomicUsize::new(0));
    let output_limit_exceeded = Arc::new(AtomicBool::new(false));
    let stdout_limit = output_limit.map(|limit| {
        (
            limit,
            Arc::clone(&bytes_read),
            Arc::clone(&output_limit_exceeded),
        )
    });
    let stderr_limit = output_limit.map(|limit| {
        (
            limit,
            Arc::clone(&bytes_read),
            Arc::clone(&output_limit_exceeded),
        )
    });
    let stdout_reader = thread::spawn(move || read_output(stdout, stdout_limit));
    let stderr_reader = thread::spawn(move || read_output(stderr, stderr_limit));

    let deadline = timeout.map(|duration| Instant::now() + duration);
    let mut child_status = None;
    let (status, timed_out) = loop {
        if output_limit.is_some() && output_limit_exceeded.load(Ordering::Acquire) {
            kill_process_group(&mut child);
            break (child_status.or_else(|| child.wait().ok())?, false);
        }
        if child_status.is_none() {
            child_status = child.try_wait().ok()?;
        }
        if child_status.is_some()
            && (output_limit.is_none()
                || (stdout_reader.is_finished() && stderr_reader.is_finished()))
        {
            break (child_status?, false);
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            kill_process_group(&mut child);
            break (child_status.or_else(|| child.wait().ok())?, true);
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout_bytes = stdout_reader.join().ok()??;
    let stderr_bytes = stderr_reader.join().ok()??;
    let _ = stdin_writer.join();
    if output_limit_exceeded.load(Ordering::Acquire) {
        return Some(output_limit_failure());
    }
    let stderr_text = String::from_utf8_lossy(&stderr_bytes).into_owned();
    let mut stdout_text = String::from_utf8_lossy(&stdout_bytes).into_owned();
    stdout_text.push_str(&stderr_text);
    if timed_out {
        stdout_text.push_str(&format!(
            "\nTimed out after {} seconds.",
            timeout.unwrap_or_default().as_secs()
        ));
    }
    Some(ProcessOutput {
        success: !timed_out && status.success(),
        exit_code: if timed_out { Some(124) } else { status.code() },
        stdout: stdout_text,
        stderr: stderr_text,
    })
}

fn kill_process_group(child: &mut std::process::Child) {
    // SAFETY: every child is placed into a new process group whose ID is its
    // PID. Killing that group prevents descendants from retaining captured
    // pipes after a timeout or output-limit failure.
    let group_killed = unsafe { libc::killpg(child.id() as i32, libc::SIGKILL) } == 0;
    if !group_killed {
        let _ = child.kill();
    }
}

fn read_all(mut pipe: impl Read) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

type OutputLimitState = (usize, Arc<AtomicUsize>, Arc<AtomicBool>);

fn read_output(pipe: impl Read, limit: Option<OutputLimitState>) -> Option<Vec<u8>> {
    match limit {
        Some((limit_bytes, bytes_read, exceeded)) => {
            read_to_limit(pipe, limit_bytes, bytes_read, exceeded)
        }
        None => read_all(pipe),
    }
}

fn read_to_limit(
    mut pipe: impl Read,
    limit_bytes: usize,
    bytes_read: Arc<AtomicUsize>,
    output_limit_exceeded: Arc<AtomicBool>,
) -> Option<Vec<u8>> {
    let mut retained = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        if output_limit_exceeded.load(Ordering::Acquire) {
            return Some(retained);
        }
        let count = pipe.read(&mut chunk).ok()?;
        if count == 0 {
            return Some(retained);
        }
        let previous = bytes_read
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                Some(used.saturating_add(count))
            })
            .ok()?;
        let remaining = limit_bytes.saturating_sub(previous);
        let retained_count = count.min(remaining);
        retained.extend_from_slice(&chunk[..retained_count]);
        if retained_count != count {
            output_limit_exceeded.store(true, Ordering::Release);
            return Some(retained);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{Seek, SeekFrom};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::time::Instant;

    #[test]
    fn captures_combined_process_output() {
        let output = SystemCommandRunner
            .run("sh", &["-c", "printf out; printf err >&2"])
            .unwrap();
        assert!(output.success);
        assert_eq!(output.stdout, "outerr");
        assert_eq!(output.stderr, "err");
    }

    #[test]
    fn enforces_process_timeout() {
        let output = SystemCommandRunner
            .run_with(
                "sh",
                &["-c", "sleep 2"],
                None,
                None,
                Some(Duration::from_millis(10)),
            )
            .unwrap();
        assert!(!output.success);
        assert_eq!(output.exit_code, Some(124));
        assert!(output.stdout.contains("Timed out after 0 seconds."));
    }

    #[test]
    fn sends_stdin_without_deadlocking_output_collection() {
        let body = vec![b'x'; 128 * 1024];
        let output = SystemCommandRunner
            .run_with_input(
                "sh",
                &["-c", "cat >/dev/null; printf done"],
                None,
                None,
                Some(Duration::from_secs(1)),
                Some(&body),
            )
            .unwrap();
        assert!(output.success);
        assert_eq!(output.stdout, "done");
    }

    #[test]
    fn output_limit_allows_under_and_exact_caps() {
        let under = SystemCommandRunner
            .run_with_output_limit(
                "sh",
                &["-c", "printf abc"],
                None,
                None,
                Some(Duration::from_secs(1)),
                4,
            )
            .unwrap();
        assert!(under.success);
        assert_eq!(under.stdout, "abc");

        let exact = SystemCommandRunner
            .run_with_output_limit(
                "sh",
                &["-c", "printf abc; printf de >&2"],
                None,
                None,
                Some(Duration::from_secs(1)),
                5,
            )
            .unwrap();
        assert!(exact.success);
        assert_eq!(exact.stdout, "abcde");
        assert_eq!(exact.stderr, "de");
    }

    #[test]
    fn output_limit_rejects_one_byte_over_with_stable_output() {
        let output = SystemCommandRunner
            .run_with_output_limit(
                "sh",
                &["-c", "printf abcde"],
                None,
                None,
                Some(Duration::from_secs(1)),
                4,
            )
            .unwrap();
        assert_eq!(output, output_limit_failure());
    }

    #[test]
    fn output_limit_counts_stdout_and_stderr_together() {
        let output = SystemCommandRunner
            .run_with_output_limit(
                "sh",
                &["-c", "printf abc; printf def >&2"],
                None,
                None,
                Some(Duration::from_secs(1)),
                5,
            )
            .unwrap();
        assert_eq!(output, output_limit_failure());
    }

    #[test]
    fn output_limit_kills_emitting_descendants_promptly() {
        let started = Instant::now();
        let output = SystemCommandRunner
            .run_with_output_limit(
                "sh",
                &["-c", "(while :; do printf x; done) &"],
                None,
                None,
                Some(Duration::from_secs(5)),
                1024,
            )
            .unwrap();
        assert_eq!(output, output_limit_failure());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn default_output_limit_preserves_mock_runner_compatibility() {
        struct MockRunner;

        impl CommandRunner for MockRunner {
            fn run(&self, _program: &str, _args: &[&str]) -> Option<ProcessOutput> {
                Some(ProcessOutput {
                    success: true,
                    exit_code: Some(0),
                    stdout: "abc".into(),
                    stderr: "de".into(),
                })
            }
        }

        let exact = MockRunner
            .run_with_output_limit("mock", &[], None, None, None, 5)
            .unwrap();
        assert!(exact.success);
        let over = MockRunner
            .run_with_output_limit("mock", &[], None, None, None, 4)
            .unwrap();
        assert_eq!(over, output_limit_failure());
    }

    #[test]
    fn explicitly_inherited_descriptor_survives_exec() {
        let name = CString::new("yafvsctl-process-test").unwrap();
        // SAFETY: name is a valid C string and the result is checked.
        let raw = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        assert!(raw >= 0);
        // SAFETY: memfd_create returned a new owned descriptor.
        let mut file = unsafe { File::from_raw_fd(raw) };
        file.write_all(b"descriptor-only-value").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let fd = file.as_raw_fd();
        let fd_text = fd.to_string();
        let output = SystemCommandRunner
            .run_with_input_and_fd(
                "sh",
                &["-c", "cat \"/proc/self/fd/$1\"", "sh", &fd_text],
                None,
                None,
                Some(Duration::from_secs(1)),
                None,
                fd,
            )
            .unwrap();
        assert!(output.success);
        assert_eq!(output.stdout, "descriptor-only-value");
    }

    #[test]
    fn exact_descriptor_set_survives_exec_and_file_limit_is_enforced() {
        let first_name = CString::new("yafvsctl-process-first").unwrap();
        let second_name = CString::new("yafvsctl-process-second").unwrap();
        let excluded_name = CString::new("yafvsctl-process-excluded").unwrap();
        // SAFETY: names are valid C strings and both results are checked.
        let first_raw = unsafe { libc::memfd_create(first_name.as_ptr(), libc::MFD_CLOEXEC) };
        let second_raw = unsafe { libc::memfd_create(second_name.as_ptr(), libc::MFD_CLOEXEC) };
        let excluded_raw = unsafe { libc::memfd_create(excluded_name.as_ptr(), 0) };
        assert!(first_raw >= 0 && second_raw >= 0 && excluded_raw >= 0);
        // SAFETY: memfd_create returned new owned descriptors.
        let mut first = unsafe { File::from_raw_fd(first_raw) };
        // SAFETY: memfd_create returned a new owned descriptor.
        let mut second = unsafe { File::from_raw_fd(second_raw) };
        // SAFETY: memfd_create returned a new owned descriptor.
        let excluded = unsafe { File::from_raw_fd(excluded_raw) };
        first.write_all(b"first").unwrap();
        second.write_all(b"second").unwrap();
        first.seek(SeekFrom::Start(0)).unwrap();
        second.seek(SeekFrom::Start(0)).unwrap();
        let first_fd = first.as_raw_fd();
        let second_fd = second.as_raw_fd();
        let excluded_fd = excluded.as_raw_fd();
        let output = SystemCommandRunner
            .run_with_input_and_fds(
                "sh",
                &[
                    "-c",
                    "test ! -e \"/proc/self/fd/$3\"; cat \"/proc/self/fd/$1\"; cat \"/proc/self/fd/$2\"",
                    "sh",
                    &first_fd.to_string(),
                    &second_fd.to_string(),
                    &excluded_fd.to_string(),
                ],
                None,
                None,
                Some(Duration::from_secs(1)),
                None,
                &[first_fd, second_fd],
                None,
            )
            .unwrap();
        assert!(output.success);
        assert_eq!(output.stdout, "firstsecond");

        let limited_name = CString::new("yafvsctl-process-limited").unwrap();
        // SAFETY: name is valid and the result is checked.
        let limited_raw = unsafe { libc::memfd_create(limited_name.as_ptr(), libc::MFD_CLOEXEC) };
        assert!(limited_raw >= 0);
        // SAFETY: memfd_create returned a new owned descriptor.
        let limited = unsafe { File::from_raw_fd(limited_raw) };
        let limited_fd = limited.as_raw_fd();
        let output = SystemCommandRunner
            .run_with_input_and_fds(
                "sh",
                &[
                    "-c",
                    "printf xx >\"/proc/self/fd/$1\"",
                    "sh",
                    &limited_fd.to_string(),
                ],
                None,
                None,
                Some(Duration::from_secs(1)),
                None,
                &[limited_fd],
                Some(1),
            )
            .unwrap();
        assert!(!output.success);
        assert!(limited.metadata().unwrap().len() <= 1);
    }
}
