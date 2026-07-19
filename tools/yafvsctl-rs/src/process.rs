// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

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

fn run_system_with_input(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    env: Option<&BTreeMap<OsString, OsString>>,
    timeout: Option<Duration>,
    input: Option<&[u8]>,
    inherited_fd: Option<RawFd>,
) -> Option<ProcessOutput> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.process_group(0);
    if let Some(fd) = inherited_fd {
        // SAFETY: pre_exec runs after fork and before exec. fcntl is
        // async-signal-safe, and the supplied descriptor remains owned by the
        // parent for the duration of this synchronous command.
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
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
    let stdout_reader = thread::spawn(move || read_all(stdout));
    let stderr_reader = thread::spawn(move || read_all(stderr));

    let deadline = timeout.map(|duration| Instant::now() + duration);
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait().ok()? {
            break (status, false);
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            // SAFETY: the child was placed into a new process group whose ID is
            // its PID. Killing that group prevents descendants from retaining
            // the captured pipes after a timeout.
            let group_killed = unsafe { libc::killpg(child.id() as i32, libc::SIGKILL) } == 0;
            if !group_killed {
                let _ = child.kill();
            }
            break (child.wait().ok()?, true);
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout_bytes = stdout_reader.join().ok()??;
    let stderr_bytes = stderr_reader.join().ok()??;
    let _ = stdin_writer.join();
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

fn read_all(mut pipe: impl Read) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{Seek, SeekFrom};
    use std::os::fd::{AsRawFd, FromRawFd};

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
}
