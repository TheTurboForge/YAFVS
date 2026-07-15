// SPDX-FileCopyrightText: 2025 Greenbone AG
// TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::time::Duration;

use crate::nasl::builtin::ssh::error::SshErrorKind;
use crate::nasl::utils::error::WithErrorInfo;

use super::{
    super::{checked_output_len, error::Result},
    SessionId,
};

/// Wrapper around a `libssh_rs::Channel`. Exposes the
/// methods of the inner channel and performs error conversions.
pub struct Channel {
    channel: libssh_rs::Channel,
    session_id: SessionId,
}

impl Channel {
    pub fn new(channel: libssh_rs::Channel, session_id: SessionId) -> Self {
        Self {
            channel,
            session_id,
        }
    }

    pub fn request_subsystem(&self, subsystem: &str) -> Result<()> {
        self.channel.request_subsystem(subsystem).map_err(|e| {
            SshErrorKind::RequestSubsystem(subsystem.to_string())
                .with(e)
                .with(self.session_id)
        })
    }

    pub fn open_session(&self) -> Result<()> {
        self.channel
            .open_session()
            .map_err(|e| SshErrorKind::OpenSession.with(self.session_id).with(e))
    }

    fn is_closed(&self) -> bool {
        self.channel.is_closed()
    }

    pub fn close(&self) -> Result<()> {
        self.channel
            .close()
            .map_err(|e| SshErrorKind::Close.with(self.session_id).with(e))
    }

    pub fn stdin(&self) -> impl std::io::Write + '_ {
        self.channel.stdin()
    }

    pub fn request_pty(&self, term: &str, columns: u32, rows: u32) -> Result<()> {
        self.channel
            .request_pty(term, columns, rows)
            .map_err(|e| SshErrorKind::RequestPty.with(self.session_id).with(e))
    }

    pub fn request_exec(&self, command: &str) -> Result<()> {
        self.channel.request_exec(command).map_err(|e| {
            SshErrorKind::RequestExec(command.to_string())
                .with(self.session_id)
                .with(e)
        })
    }

    pub fn request_shell(&self) -> Result<()> {
        self.channel
            .request_shell()
            .map_err(|e| SshErrorKind::RequestShell.with(self.session_id).with(e))
    }

    pub fn ensure_open(&self) -> Result<()> {
        if self.is_closed() {
            Err(SshErrorKind::ChannelClosed.with(self.session_id))
        } else {
            Ok(())
        }
    }

    fn buf_as_str<'a>(&self, buf: &'a [u8]) -> Result<&'a str> {
        std::str::from_utf8(buf).map_err(|_| SshErrorKind::ReadSsh.with(self.session_id))
    }

    pub fn read_timeout(
        &self,
        timeout: Duration,
        stderr: bool,
        retained: &mut usize,
    ) -> Result<String> {
        let mut buf: [u8; 4096] = [0; 4096];
        let mut response = String::new();
        loop {
            match self.channel.read_timeout(&mut buf, stderr, Some(timeout)) {
                Ok(0) => break,
                Ok(num_bytes) => {
                    let chunk = self.buf_as_str(&buf[..num_bytes])?;
                    *retained = checked_output_len(self.session_id, *retained, chunk.len())?;
                    response.push_str(chunk);
                }
                Err(libssh_rs::Error::TryAgain) => {}
                Err(_) => {
                    return Err(SshErrorKind::ReadSsh.with(self.session_id));
                }
            }
        }
        Ok(response)
    }

    pub fn read_ssh_blocking(&self, timeout: Duration) -> Result<String> {
        let mut retained = 0;
        let stderr = self.read_timeout(timeout, true, &mut retained)?;
        let stdout = self.read_timeout(timeout, false, &mut retained)?;
        Ok(format!("{stderr}{stdout}"))
    }

    fn read_nonblocking(&self, stderr: bool, retained: &mut usize) -> Result<String> {
        let mut buf: [u8; 4096] = [0; 4096];
        match self.channel.read_nonblocking(&mut buf, stderr) {
            Ok(n) => {
                let response = self.buf_as_str(&buf[..n])?;
                *retained = checked_output_len(self.session_id, *retained, response.len())?;
                let response = response.to_string();
                Ok(response)
            }
            Err(_) => Err(SshErrorKind::ReadSsh.with(self.session_id)),
        }
    }

    pub fn read_ssh_nonblocking(&self) -> Result<String> {
        if self.channel.is_closed() || self.channel.is_eof() {
            return Err(SshErrorKind::ReadSsh.with(self.session_id));
        }

        let mut retained = 0;
        let stderr = self.read_nonblocking(true, &mut retained)?;
        let stdout = self.read_nonblocking(false, &mut retained)?;
        Ok(format!("{stderr}{stdout}"))
    }
}
