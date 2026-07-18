// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) use crate::{
    browser_proxy_routes::browser_proxy_native_api_router,
    direct_api_routes::direct_native_api_router, read_api_routes::native_api_router,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser_proxy_api::BrowserProxyAuth;

    #[test]
    fn route_tables_build_without_conflicts() {
        let base_router = native_api_router();
        let _direct_read_router = direct_native_api_router(base_router, false);
        let _direct_write_router = direct_native_api_router(native_api_router(), true);
        let _browser_proxy_router = browser_proxy_native_api_router(native_api_router(), None);
        let _browser_write_router = browser_proxy_native_api_router(
            native_api_router(),
            Some(BrowserProxyAuth::new(
                "0123456789abcdef0123456789abcdef".to_string(),
            )),
        );
    }
}
