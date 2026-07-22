<!-- TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>. -->

# Authentication Methods in gvmd (HTTP Scanner)

The current `gvmd` implementation supports two authentication methods for communication with external HTTP scanner components.

## Supported Methods

- **Certificates (mTLS)**
- **API Key** (`X-API-KEY`)

---

## 1. Certificates (mTLS)

This method uses **X.509 certificates**, where access is controlled based on a Certificate Authority (CA).  
Certificates are configured on the scanner, and `gvmd` uses them to establish a mutual TLS connection.

### Certificate Creation for mTLS

To set up certificate-based authentication, you need a CA certificate and client/server certificates.  
The `openvas-scanner` repository provides helper scripts and examples to generate these:

- Create a CA certificate
- Generate server and client certificates signed by this CA
- Configure gvmd and the scanner with the generated files

Detailed examples and scripts are available here:  
[openvas-scanner: rust/examples/tls](https://github.com/greenbone/openvas-scanner/tree/main/rust/examples/tls)

### Configure certificates for a scanner

YAFVS native scanner configuration owns scanner endpoint, relay, and
certificate references. Use the authenticated native full-configuration
replacement contract documented in the
[YAFVS API contract](../../../docs/API_CONTRACT.md); the removed `gvmd`
scanner mutation options cannot configure these values. Remote TLS/relay
verification and external relay-file synchronization remain inherited
compatibility behavior.

---

## 2. API Key–like Tokens

This method uses a static token that must be provided with each request.
Depending on the component, the token is included in the request header:

* **HTTP Scanner:** `X-API-KEY: <token>`

Both behave the same way for authentication/authorization.

### Example: HTTP Scanner request with API Key

```c
if (apikey)
  {
    GString *xapikey = g_string_new ("X-API-KEY: ");
    g_string_append (xapikey, apikey);

    if (!gvm_http_add_header (headers, xapikey->str))
      g_warning ("%s: Not possible to set API-KEY", __func__);

    g_string_free (xapikey, TRUE);
  }
```

HTTP Header example:

```http
X-API-KEY: <your_api_key_here>
```

---

## Notes

* For the **HTTP Scanner**, **Certificates (mTLS)** is currently supported.
* Authentication modes are configured either via **configuration files** or by passing arguments when starting `gvmd`.