// SPDX-FileCopyrightText: 2026 Greenbone AG
// TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests;

use std::collections::HashMap;

use greenbone_scanner_framework::models::FixedVersion;
use nasl_function_proc_macro::nasl_function;

use crate::{
    function_set,
    nasl::{ArgumentError, FnError, NaslValue, ScanCtx, utils::scan_ctx::NotusCtx},
    notus::Notus,
};

fn parse_package_list(value: NaslValue) -> Result<Vec<String>, ArgumentError> {
    match value {
        NaslValue::String(value) => Ok(value
            .split([',', '\n', '\r'])
            .map(str::trim)
            .filter(|package| !package.is_empty())
            .map(str::to_owned)
            .collect()),
        NaslValue::Array(values) => Ok(values
            .iter()
            .map(ToString::to_string)
            .map(|package| package.trim().to_owned())
            .filter(|package| !package.is_empty())
            .collect()),
        value => Err(ArgumentError::wrong_argument(
            "pkg_list",
            "String as Comma or Newline Separated List or Array of Strings",
            &format!("{:?}", value),
        )),
    }
}

#[nasl_function]
fn notus_type() -> i64 {
    1
}

impl NaslNotus {
    fn notus_self(
        &self,
        notus: &mut Notus,
        pkg_list: &[String],
        product: &str,
    ) -> Result<NaslValue, FnError> {
        let res = notus.scan(product, pkg_list)?;

        let mut ret = vec![];
        for (oid, vuls) in res {
            let mut dict = HashMap::new();
            let message = vuls.into_iter().map(|vul| match vul.fixed_version {
                FixedVersion::Single { version, specifier } => format!("Vulnerable package:   {}\nInstalled version:    {}-{}\nFixed version:      {:2}{}-{}", vul.name, vul.name, vul.installed_version, specifier.to_string(), vul.name, version),
                FixedVersion::Range { start, end } => format!("Vulnerable package:   {}\nInstalled version:    {}-{}\nFixed version:      < {}-{}\nFixed version:      >={}-{}", vul.name, vul.name, vul.installed_version, vul.name, start, vul.name, end),
            }).collect::<Vec<String>>().join("\n\n");
            dict.insert("oid".to_string(), NaslValue::String(oid));
            dict.insert("message".to_string(), NaslValue::String(message));
            ret.push(NaslValue::Dict(dict))
        }
        Ok(NaslValue::Array(ret))
    }

    /// Returns the last error message from the Notus function.
    #[nasl_function]
    fn notus_error(&self) -> Option<String> {
        self.last_error.clone()
    }

    /// This function takes the given information and starts a notus scan. Its arguments are:
    /// pkg_list: comma separated list or array of installed packages of the target system
    /// product: identifier for the notus scanner to get list of vulnerable packages
    ///
    /// This function returns a json like structure,
    /// so information can be adjusted and must be published using
    /// security_notus. The json like format depends
    /// one the scanner that is used.
    /// The format of the result has the following structure:
    /// ```json
    /// [
    ///   {
    ///     "oid": "[oid1]",
    ///     "message": "[message1]"
    ///   },
    ///   {
    ///     "oid": "[oid2]",
    ///     "message": "[message2]"
    ///   }
    /// ]
    /// ```
    /// It is a list of dictionaries. Each dictionary has the key `oid` and `message`.
    ///
    /// In case of an Error a NULL value is returned and an Error is set. The error can be gathered using the
    /// notus_error function, which yields the last occurred error.
    ///
    /// The internal Notus implementation uses the configured local feed.
    #[nasl_function(named(pkg_list, product))]
    async fn notus(
        &mut self,
        context: &ScanCtx<'_>,
        pkg_list: NaslValue,
        product: &str,
    ) -> Result<NaslValue, FnError> {
        let notus = if let Some(notus) = &context.notus {
            notus
        } else {
            self.last_error = Some("Configuration Error: Notus context not found".to_string());
            return Ok(NaslValue::Null);
        };
        let pkg_list = parse_package_list(pkg_list)?;
        let NotusCtx::Direct(notus) = notus;
        let ret = self.notus_self(&mut notus.lock().unwrap(), &pkg_list, product);
        match ret {
            Err(e) => {
                self.last_error = Some(e.to_string());
                Ok(NaslValue::Null)
            }
            Ok(ret) => {
                self.last_error = None;
                Ok(ret)
            }
        }
    }
}

#[derive(Default)]
pub struct NaslNotus {
    last_error: Option<String>,
}

function_set! {
    NaslNotus,
    (
        (NaslNotus::notus_error, "notus_error"),
        (NaslNotus::notus, "notus"),
        notus_type
    )
}
