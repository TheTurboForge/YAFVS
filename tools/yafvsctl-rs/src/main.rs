// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::env;
use std::process::ExitCode;
use yafvsctl::{current_dir, exit_code, parse_cli, render_human, render_json, run};

fn main() -> ExitCode {
    let cli = match parse_cli(env::args_os().skip(1)) {
        Ok(cli) => cli,
        Err(error) => {
            let _ = error.print();
            return ExitCode::from(2);
        }
    };
    let cwd = match current_dir() {
        Ok(cwd) => cwd,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(1);
        }
    };
    let result = run(&cli, &cwd);
    let rendered = if cli.json {
        render_json(&result).unwrap_or_else(|error| {
            format!("{{\"status\":\"fail\",\"summary\":\"JSON serialization failed: {error}\"}}\n")
        })
    } else {
        render_human(&result)
    };
    print!("{rendered}");
    ExitCode::from(exit_code(&result) as u8)
}
