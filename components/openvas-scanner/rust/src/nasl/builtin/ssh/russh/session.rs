// SPDX-FileCopyrightText: 2025 Greenbone AG
// TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::borrow::Cow;
use std::time::Duration;
use std::{net::IpAddr, sync::Arc};

use async_trait::async_trait;
use client::{DisconnectReason, Session, connect};
use russh::keys::{Algorithm, HashAlg};
use russh::*;
use tracing::{error, warn};

use crate::nasl::builtin::ssh::error::SshErrorKind;
use crate::nasl::builtin::ssh::host_key_policy::HostKeyPolicy;
use crate::nasl::builtin::ssh::{Output, check_lossy_output_chunk, checked_output_len};
use crate::nasl::utils::error::WithErrorInfo;

use super::super::error::SshError;
use super::{AuthMethods, Port, SessionId, Socket};

struct Client {
    host_key_policy: Option<HostKeyPolicy>,
}

#[async_trait]
impl client::Handler for Client {
    type Error = russh::Error;

    #[allow(clippy::manual_async_fn)]
    fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        let accepted = self.host_key_policy.as_ref().is_none_or(|policy| {
            policy.accepts_digest(server_public_key.fingerprint(HashAlg::Sha256).as_bytes())
        });
        async move { Ok(accepted) }
    }

    #[allow(unused_variables)]
    #[allow(clippy::manual_async_fn)]
    fn channel_open_confirmation(
        &mut self,
        id: ChannelId,
        max_packet_size: u32,
        window_size: u32,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    #[allow(clippy::manual_async_fn)]
    fn channel_close(
        &mut self,
        _: ChannelId,
        _: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    #[allow(clippy::manual_async_fn)]
    fn data(
        &mut self,
        _: ChannelId,
        _: &[u8],
        _: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    /// Called when the server sent a disconnect message
    ///
    /// If reason is an Error, this function should re-return the error so the join can also evaluate it
    #[allow(clippy::manual_async_fn)]
    fn disconnected(
        &mut self,
        reason: DisconnectReason<Self::Error>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async {
            match reason {
                DisconnectReason::ReceivedDisconnect(_) => Ok(()),
                DisconnectReason::Error(e) => {
                    match e {
                        russh::Error::Disconnect => {}
                        _ => {
                            error!("SSH session disconnected due to error: {}", e);
                        }
                    }
                    Err(e)
                }
            }
        }
    }
}

/// This struct is a convenience wrapper
/// around a russh client
pub struct SshSession {
    id: SessionId,
    session: client::Handle<Client>,
}

impl SshSession {
    // The alternative to many arguments here is making
    // the fields public or creating some sort of builder struct
    // both of which feel like much worse alternatives.
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        id: SessionId,
        ip_addr: IpAddr,
        port: Port,
        timeout: Option<Duration>,
        keytype: Vec<Algorithm>,
        csciphers: Vec<cipher::Name>,
        scciphers: Vec<cipher::Name>,
        socket: Option<Socket>,
        host_key_policy: Option<HostKeyPolicy>,
    ) -> Result<Self, SshError> {
        if socket.is_some() {
            error!("Using custom sockets not yet implemented.");
            return Err(SshErrorKind::Unimplemented.with(id));
        }
        let preferred = construct_preferred(keytype, csciphers, scciphers);
        let config = client::Config {
            inactivity_timeout: timeout,
            preferred,
            ..Default::default()
        };

        let config = Arc::new(config);
        let verification_required = host_key_policy.is_some();
        let sh = Client { host_key_policy };

        let session = connect(config, (ip_addr, port), sh)
            .await
            .map_err(|error| {
                if verification_required && matches!(error, russh::Error::UnknownKey) {
                    SshErrorKind::HostKeyPinMismatch.with(id)
                } else {
                    SshErrorKind::Connect.with(id).with(error)
                }
            })?;

        Ok(Self { session, id })
    }

    pub(crate) async fn exec_ssh_cmd(&self, command: &str) -> Result<Output, SshError> {
        let (stdout, stderr) = self.call(command).await?;
        Ok(Output {
            stdout,
            stderr,
            session_id: self.id,
        })
    }

    async fn call(&self, command: &str) -> Result<(String, String), SshError> {
        let request_error = |error| {
            SshErrorKind::RequestExec(command.to_string())
                .with(self.id)
                .with(error)
        };
        let mut channel = self
            .session
            .channel_open_session()
            .await
            .map_err(request_error)?;
        channel.exec(true, command).await.map_err(request_error)?;

        let mut code = None;
        let mut stdout = String::new();
        let mut stderr = String::new();
        let mut retained = 0;

        loop {
            // There's an event available on the session channel
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                // Write data to the terminal
                ChannelMsg::Data { ref data } => {
                    check_lossy_output_chunk(self.id, data.len())?;
                    let chunk = String::from_utf8_lossy(data);
                    retained = checked_output_len(self.id, retained, chunk.len())?;
                    stdout.push_str(&chunk);
                }
                ChannelMsg::ExtendedData { ref data, .. } => {
                    check_lossy_output_chunk(self.id, data.len())?;
                    let chunk = String::from_utf8_lossy(data);
                    retained = checked_output_len(self.id, retained, chunk.len())?;
                    stderr.push_str(&chunk);
                }
                // The command has returned an exit code
                ChannelMsg::ExitStatus { exit_status } => {
                    code = Some(exit_status);
                    // cannot leave the loop immediately, there might still be more data to receive
                    channel.eof().await.map_err(request_error)?;
                }
                _ => {}
            }
        }
        if code.is_none() {
            warn!("Program did not exit cleanly: {}", command);
        }
        Ok((stdout.to_string(), stderr.to_string()))
    }

    pub async fn auth_password(&mut self, login: &str, password: &str) -> Result<(), SshError> {
        self.session
            .authenticate_password(login, password)
            .await
            .map_err(|_| SshErrorKind::UserAuthPassword.with(self.id))
            .map(|_| ())
    }

    pub async fn auth_keyboard_interactive(
        &mut self,
        login: &str,
        password: &str,
    ) -> Result<(), SshError> {
        let make_err = || SshErrorKind::UserAuthKeyboardInteractive.with(self.id);
        let response = self
            .session
            .authenticate_keyboard_interactive_start(login, None)
            .await
            .map_err(|_| make_err())?;
        match response {
            client::KeyboardInteractiveAuthResponse::Success => Ok(()),
            client::KeyboardInteractiveAuthResponse::Failure { .. } => Err(make_err()),
            client::KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let mut answers: Vec<String> = Vec::new();
                for p in prompts.into_iter() {
                    if !p.echo {
                        answers.push(password.to_string());
                    } else {
                        answers.push(String::new());
                    };
                }
                self.session
                    .authenticate_keyboard_interactive_respond(answers)
                    .await
                    .map_err(|_| make_err())
                    .map(|_| ())
            }
        }
    }

    pub async fn auth_method_allowed(&mut self, _method: AuthMethods) -> Result<bool, SshError> {
        // TODO: Actually check which auth methods are allowed.
        // Don't really know how to do this
        Ok(true)
    }
}

fn construct_preferred(
    keytype: Vec<Algorithm>,
    csciphers: Vec<cipher::Name>,
    scciphers: Vec<cipher::Name>,
) -> Preferred {
    // Only keep the intersection of scciphers and csciphers.
    let ciphers = csciphers
        .into_iter()
        .filter(|cs| scciphers.iter().any(|sc| sc == cs))
        .collect::<Vec<_>>();
    Preferred {
        key: Cow::from(keytype),
        cipher: Cow::from(ciphers),
        ..Preferred::DEFAULT
    }
}
