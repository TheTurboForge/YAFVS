# SPDX-FileCopyrightText: 2025 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
http client for initializing a connection to the openvasd HTTP API using optional mTLS authentication.
"""

import ssl
from os import PathLike

from httpx import Client

StrOrPathLike = str | PathLike[str]


def create_openvasd_http_client(
    host_name: str,
    *,
    api_key: str | None = None,
    server_ca_path: StrOrPathLike | None = None,
    client_cert_paths: StrOrPathLike
    | tuple[StrOrPathLike, StrOrPathLike]
    | None = None,
    port: int = 3000,
) -> Client:
    """
    Create a `httpx.Client` configured for mTLS-secured or API KEY access
    to an openvasd HTTP API instance.

    Args:
        host_name: Hostname or IP of the OpenVASD server (e.g., "localhost").
        api_key: Optional API key used for authentication via HTTP headers.
        server_ca_path: Path to the server's CA certificate (for verifying the server).
        client_cert_paths: Path to the client certificate (str) or a tuple of
                            (cert_path, key_path) for mTLS authentication.
        port: The port to connect to (default: 3000).

    Behavior:
        - HTTPS and certificate verification are enabled by default.
        - If `server_ca_path` is set, it is used as the trust root for server
          verification.
        - If `client_cert_paths` is set, the certificate is used for mTLS client
          authentication.
    """
    headers = {}

    verify: bool | ssl.SSLContext | StrOrPathLike = True

    if server_ca_path:
        context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH, cafile=server_ca_path
        )
        context.verify_mode = ssl.CERT_REQUIRED
        verify = context

    if client_cert_paths and isinstance(verify, ssl.SSLContext):
        if isinstance(client_cert_paths, tuple):
            verify.load_cert_chain(
                certfile=client_cert_paths[0], keyfile=client_cert_paths[1]
            )
        else:
            verify.load_cert_chain(certfile=client_cert_paths)

    cert: StrOrPathLike | tuple[StrOrPathLike, StrOrPathLike] | None = None
    if client_cert_paths and not isinstance(verify, ssl.SSLContext):
        cert = client_cert_paths

    if api_key:
        headers["X-API-KEY"] = api_key

    base_url = f"https://{host_name}:{port}"

    return Client(
        base_url=base_url,
        headers=headers,
        verify=verify,
        cert=cert,
        http2=True,
        timeout=10.0,
    )
