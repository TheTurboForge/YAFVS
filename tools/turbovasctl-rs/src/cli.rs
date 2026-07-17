// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use clap::{Parser, Subcommand};
use std::ffi::OsString;

#[derive(Debug, Parser, PartialEq, Eq)]
#[command(name = "turbovasctl", disable_help_subcommand = true)]
pub struct Cli {
    /// Emit machine-readable JSON.
    #[arg(long, global = true)]
    pub json: bool,

    /// Request a compact status-oriented response where the command supports it.
    #[arg(long, global = true)]
    pub status_only: bool,

    #[command(subcommand)]
    pub command: CliCommand,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum CliCommand {
    /// Show repository status.
    Status,
    /// Show expected component inventory.
    Inventory {
        /// Limit inventory to a path under the repository.
        #[arg(long)]
        scope: Option<String>,
    },
    /// Show branding and upstream-identity state.
    BrandingState,
    /// Inspect absolute checkout/runtime path coupling.
    PathCouplingState,
}

pub fn parse_cli<I, S>(args: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString> + Clone,
{
    Cli::try_parse_from(
        std::iter::once(OsString::from("turbovasctl")).chain(args.into_iter().map(Into::into)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_global_flags_before_or_after_subcommands() {
        assert_eq!(
            parse_cli(["--json", "status"]).unwrap(),
            Cli {
                command: CliCommand::Status,
                json: true,
                status_only: false,
            }
        );
        assert_eq!(
            parse_cli(["inventory", "--scope", "components/gsa", "--json"]).unwrap(),
            Cli {
                command: CliCommand::Inventory {
                    scope: Some("components/gsa".to_string()),
                },
                json: true,
                status_only: false,
            }
        );
    }

    #[test]
    fn rejects_inventory_scope_on_status() {
        assert!(parse_cli(["status", "--scope", "components"]).is_err());
    }

    #[test]
    fn parses_status_only_as_a_global_flag() {
        assert_eq!(
            parse_cli(["inventory", "--status-only"]).unwrap(),
            Cli {
                command: CliCommand::Inventory { scope: None },
                json: false,
                status_only: true,
            }
        );
    }
}
