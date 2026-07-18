/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import HttpCommand from 'gmp/commands/http';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';

interface NativeApiErrorPayload {
  error?: {
    code?: unknown;
    message?: unknown;
  };
}

export class AuthenticationSettingsRequestError extends Error {
  readonly code?: string;

  constructor(status: number, code?: string, message?: string) {
    super(
      [`Native API request failed with status ${status}`, code, message]
        .filter(value => value !== undefined && value !== '')
        .join(': '),
    );
    this.name = 'AuthenticationSettingsRequestError';
    this.code = code;
  }
}

const nativeApiHeaders = (http: Http) => ({
  Accept: 'application/json',
  'Content-Type': 'application/json',
  ...(http.session.token ? {'X-YAFVS-Token': http.session.token} : {}),
  ...(http.session.jwt ? {Authorization: `Bearer ${http.session.jwt}`} : {}),
});

const putNativeJson = async (
  http: Http,
  path: string,
  body: Record<string, unknown>,
) => {
  const response = await fetch(http.buildUrl(path), {
    method: 'PUT',
    credentials: 'include',
    headers: nativeApiHeaders(http),
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    let payload: NativeApiErrorPayload = {};
    try {
      payload = (await response.json()) as NativeApiErrorPayload;
    } catch {
      // Preserve the HTTP status when an intermediary returned non-JSON.
    }
    const code =
      typeof payload.error?.code === 'string' ? payload.error.code : undefined;
    const message =
      typeof payload.error?.message === 'string'
        ? payload.error.message
        : undefined;
    throw new AuthenticationSettingsRequestError(
      response.status,
      code,
      message,
    );
  }
  return new Response(undefined);
};

interface SaveLdapArguments {
  authdn: string;
  allowPlaintext: boolean;
  certificate?: File;
  ldapEnabled: boolean;
  ldapHost: string;
  ldapsOnly: boolean;
}

interface SaveRadiusArguments {
  radiusEnabled: boolean;
  radiusHost: string;
  radiusKey: string;
}

class AuthenticationCommand extends HttpCommand {
  saveLdap({
    authdn,
    allowPlaintext,
    certificate,
    ldapEnabled,
    ldapHost,
    ldapsOnly,
  }: SaveLdapArguments) {
    const save = async () => {
      const body = {
        enabled: ldapEnabled,
        host: ldapHost,
        auth_dn: authdn,
        allow_plaintext: allowPlaintext,
        ldaps_only: ldapsOnly,
        ...(certificate ? {ca_certificate_pem: await certificate.text()} : {}),
      };
      return putNativeJson(
        this.http,
        'api/v1/authentication-settings/ldap',
        body,
      );
    };
    return save();
  }

  saveRadius({radiusEnabled, radiusHost, radiusKey}: SaveRadiusArguments) {
    return putNativeJson(this.http, 'api/v1/authentication-settings/radius', {
      enabled: radiusEnabled,
      host: radiusHost,
      ...(radiusKey ? {secret: radiusKey} : {}),
    });
  }
}

export default AuthenticationCommand;
