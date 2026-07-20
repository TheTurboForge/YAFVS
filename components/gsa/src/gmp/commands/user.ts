/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import Capabilities from 'gmp/capabilities/capabilities';
import Features from 'gmp/capabilities/features';
import HttpCommand, {type HttpCommandOptions} from 'gmp/commands/http';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import logger from 'gmp/log';
import date, {type Date} from 'gmp/models/date';
import Setting from 'gmp/models/setting';
import Settings from 'gmp/models/settings';
import {
  AUTH_METHOD_LDAP,
  AUTH_METHOD_NEW_PASSWORD,
  AUTH_METHOD_PASSWORD,
  AUTH_METHOD_RADIUS,
} from 'gmp/models/user';
import {
  cloneNativeUser,
  createNativeUser,
  deleteNativeUser,
  exportNativeUserMetadata,
  fetchUserManagementUser,
  patchNativeUser,
} from 'gmp/native-api/users';
import {parseInt} from 'gmp/parser';
import {forEach} from 'gmp/utils/array';
import {type EntityType} from 'gmp/utils/entity-type';
import {isDefined} from 'gmp/utils/identity';

export interface CertificateInfo {
  issuer: string;
  activationTime?: Date;
  expirationTime?: Date;
  sha256Fingerprint: string;
}

interface NativeAuthCertificate {
  activation_time?: string;
  expiration_time?: string;
  issuer?: string;
  sha256?: string;
  sha256_fingerprint?: string;
  configured?: boolean;
}

interface AuthSettingsValues {
  enabled?: boolean;
  allowPlaintext?: boolean;
  ldapsOnly?: boolean;
  certificateInfo?: CertificateInfo;
  secretConfigured?: boolean;
  [key: string]: string | boolean | CertificateInfo | undefined;
}

interface NativeAuthProvider {
  available: boolean;
  enabled: boolean;
  host: string;
  auth_dn?: string;
  allow_plaintext?: boolean;
  ldaps_only?: boolean;
  ca_certificate?: NativeAuthCertificate;
  certificate?: NativeAuthCertificate;
  secret_configured?: boolean;
}

interface NativeAuthSettingsResponse {
  ldap?: NativeAuthProvider;
  radius?: NativeAuthProvider;
}

interface CreateArguments {
  auth_method: string;
  comment: string;
  name: string;
  password?: string;
}

interface SaveArguments {
  id: string;
  auth_method: string;
  comment: string;
  name: string;
  old_name: string;
  password?: string;
}

interface DeleteArguments {
  id: string;
  inheritorId?: string;
}

const log = logger.getLogger('gmp.commands.users');

const REPORT_COMPOSER_DEFAULTS_SETTING_ID =
  'b6b449ee-5d90-4ff0-af20-7e838c389d39';

const nativeApiHeaders = (http: Http, withJsonBody = false) => ({
  Accept: 'application/json',
  ...(withJsonBody ? {'Content-Type': 'application/json'} : {}),
  ...(http.session.token ? {'X-YAFVS-Token': http.session.token} : {}),
  ...(http.session.jwt ? {Authorization: `Bearer ${http.session.jwt}`} : {}),
});

interface NativeSettingPayload {
  id: string;
  name: string;
  comment?: string;
  value?: string;
}

interface NativeSettingsPayload {
  items?: NativeSettingPayload[];
}

class NativeApiRequestError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = 'NativeApiRequestError';
  }
}

const nativeSettingToModel = (setting: NativeSettingPayload) =>
  new Setting({
    _id: setting.id,
    name: setting.name,
    comment: setting.comment,
    value: setting.value,
  });

const fetchNativeJson = async <T>(
  http: Http,
  path: string,
  includeTokenQuery = true,
): Promise<T> => {
  const response = await fetch(
    http.buildUrl(
      path,
      includeTokenQuery ? {token: http.session.token} : undefined,
    ),
    {
      method: 'GET',
      credentials: 'include',
      headers: nativeApiHeaders(http),
    },
  );
  if (!response.ok) {
    throw new NativeApiRequestError(
      `Native API request failed with status ${response.status}`,
      response.status,
    );
  }
  return (await response.json()) as T;
};

const putNativeSetting = async (
  http: Http,
  path: string,
  value: string | number,
) => {
  const response = await fetch(http.buildUrl(path), {
    method: 'PUT',
    credentials: 'include',
    headers: nativeApiHeaders(http, true),
    body: JSON.stringify({value}),
  });
  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }
  return new Response(undefined);
};

export const ROWS_PER_PAGE_SETTING_ID = '5f5a8712-8017-11e1-8556-406186ea4fc5';

export const DEFAULT_SETTINGS = {
  defaultalert: 'f9f5a546-8018-48d0-bef5-5ad4926ea899',
  defaultesxicredential: '83545bcf-0c49-4b4c-abbf-63baf82cc2a7',
  defaultopenvasscanconfig: 'fe7ea321-e3e3-4cc6-9952-da836aae83ce',
  defaultospscanconfig: 'fb19ac4b-614c-424c-b046-0bc32bf1be73',
  defaultsmbcredential: 'a25c0cfe-f977-417b-b1da-47da370c03e8',
  defaultsnmpcredential: '024550b8-868e-4b3c-98bf-99bb732f6a0d',
  defaultsshcredential: '6fc56b72-c1cf-451c-a4c4-3a9dc784c3bd',
  defaultportlist: 'd74a9ee8-7d35-4879-9485-ab23f1bd45bc',
  defaultopenvasscanner: 'f7d0f6ed-6f9e-45dc-8bd9-05cced84e80d',
  defaultospscanner: 'b20697c9-be0a-4cd4-8b4d-5fe7841ebb03',
  defaultschedule: '778eedad-5550-4de0-abb6-1320d13b5e18',
  defaulttarget: '23409203-940a-4b4a-b70c-447475f18323',
};

export const DEFAULT_FILTER_SETTINGS: Record<
  Exclude<
    EntityType,
    // info and portrange do not have filter settings
    'info' | 'portrange'
  >,
  string
> = {
  alert: 'b833a6f2-dcdc-4535-bfb0-a5154b5b5092',
  asset: '0f040d06-abf9-43a2-8f94-9de178b0e978',
  certbund: 'e4cf514a-17e2-4ab9-9c90-336f15e24750',
  cpe: '3414a107-ae46-4dea-872d-5c4479a48e8f',
  credential: '186a5ac8-fe5a-4fb1-aa22-44031fb339f3',
  cve: 'def63b5a-41ef-43f4-b9ef-03ef1665db5d',
  dfncert: '312350ed-bc06-44f3-8b3f-ab9eb828b80b',
  filter: 'f9691163-976c-47e7-ad9a-38f2d5c81649',
  host: '37562dfe-1f7e-4cae-a7c0-fa95e6f194c5',
  nvt: 'bef08b33-075c-4f8c-84f5-51f6137e40a3',
  operatingsystem: 'f608c3ec-ce73-4ff6-8e04-7532749783af',
  override: 'eaaaebf1-01ef-4c49-b7bb-955461c78e0a',
  portlist: '7d52d575-baeb-4d98-bb68-e1730dbc6236',
  report: '48ae588e-9085-41bc-abcb-3d6389cf7237',
  reportformat: '249c7a55-065c-47fb-b453-78e11a665565',
  result: '739ab810-163d-11e3-9af6-406186ea4fc5',
  scanconfig: '1a9fbd91-0182-44cd-bc88-a13a9b3b1bef',
  scanner: 'ba00fe91-bdce-483c-b8df-2372e9774ad6',
  scope: '6a0f5d70-5c88-47cb-aa31-9c3f0c73c2c6',
  scopereport: '7e30d82c-7552-4e26-8b21-ff594971b0a4',
  schedule: 'a83e321b-d994-4ae8-beec-bfb5fe3e7336',
  tag: '108eea3b-fc61-483c-9da9-046762f137a8',
  target: '236e2e41-9771-4e7a-8124-c432045985e0',
  task: '1c981851-8244-466c-92c4-865ffe05e721',
  tlscertificate: '34a176c1-0278-4c29-b84d-3d72117b2169',
  user: 'a33635be-7263-4549-bd80-c04d2dba89b4',
  vulnerability: '17c9d269-95e7-4bfa-b1b2-bc106a2175c7',
} as const;

export const saveDefaultFilterSettingId = (entityType: string) =>
  `settings_filter:${DEFAULT_FILTER_SETTINGS[entityType]}`;

export const transformSettingName = (name: string) =>
  name.toLowerCase().replace(/ |-/g, '');

const authMethodFromInput = (authMethod: string) => {
  if (authMethod === AUTH_METHOD_LDAP || authMethod === AUTH_METHOD_RADIUS) {
    return authMethod;
  }
  return AUTH_METHOD_PASSWORD;
};

class UserCommand extends HttpCommand {
  constructor(http: Http) {
    super(http);
  }

  async get({id}: {id: string}, _options: {filter?: string} = {}) {
    const user = await fetchUserManagementUser(this.http, id);
    return new Response(user);
  }

  async export({id}: {id: string}) {
    return exportNativeUserMetadata(this.http, id);
  }

  async clone({id}: {id: string}) {
    return cloneNativeUser(this.http, id);
  }

  async currentAuthSettings(_options: HttpCommandOptions = {}) {
    const data = await fetchNativeJson<NativeAuthSettingsResponse>(
      this.http,
      'api/v1/authentication-settings',
      false,
    );
    const settings = new Settings();
    const ldap = data.ldap;
    if (ldap?.available) {
      const certificate = ldap.ca_certificate ?? ldap.certificate;
      const values: AuthSettingsValues = {
        authdn: ldap.auth_dn,
        allowPlaintext: ldap.allow_plaintext,
        enabled: ldap.enabled,
        ldaphost: ldap.host,
        ldapsOnly: ldap.ldaps_only,
      };
      if (certificate && certificate.configured !== false) {
        values.certificateInfo = {
          issuer: certificate.issuer ?? '',
          sha256Fingerprint:
            certificate.sha256_fingerprint ?? certificate.sha256 ?? '',
          activationTime: certificate.activation_time
            ? date(certificate.activation_time)
            : undefined,
          expirationTime: certificate.expiration_time
            ? date(certificate.expiration_time)
            : undefined,
        };
      }
      settings.set('method:ldap_connect', values);
    }
    const radius = data.radius;
    if (radius?.available) {
      settings.set('method:radius_connect', {
        enabled: radius.enabled,
        radiushost: radius.host,
        secretConfigured: radius.secret_configured === true,
        ...(radius.secret_configured ? {radiuskey: '********'} : {}),
      });
    }
    return new Response(settings);
  }

  async getSetting(id: string) {
    try {
      const setting = await fetchNativeJson<NativeSettingPayload>(
        this.http,
        `api/v1/users/current/settings/${id}`,
      );
      return new Response(nativeSettingToModel(setting));
    } catch (error) {
      if (error instanceof NativeApiRequestError && error.status === 404) {
        return new Response<Setting | undefined>(undefined);
      }
      throw error;
    }
  }

  async currentSettings(_options: HttpCommandOptions = {}) {
    const payload = await fetchNativeJson<NativeSettingsPayload>(
      this.http,
      'api/v1/users/current/settings',
    );
    const settings: Record<string, Setting> = {};
    forEach(payload.items, setting => {
      const keyName = transformSettingName(setting.name);
      settings[keyName] = nativeSettingToModel(setting);
    });
    return new Response(settings);
  }

  async currentCapabilities() {
    return new Response(new Capabilities(['everything']));
  }

  async currentFeatures() {
    return new Response(new Features());
  }

  create({
    // eslint-disable-next-line @typescript-eslint/naming-convention
    auth_method,
    comment,
    name,
    password,
  }: CreateArguments) {
    const authMethod = authMethodFromInput(auth_method);
    log.debug('Creating new user', {
      authMethod,
      hasPassword: password !== undefined && password.length > 0,
      name,
    });
    return createNativeUser(this.http, {
      authMethod,
      comment,
      name,
      password:
        authMethod === AUTH_METHOD_PASSWORD ? (password ?? '') : undefined,
    });
  }

  save({
    id,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    auth_method,
    comment = '',
    name,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    old_name,
    password,
  }: SaveArguments) {
    const authMethod = authMethodFromInput(auth_method);
    log.debug('Saving user', {
      authMethod,
      hasPassword: password !== undefined && password.length > 0,
      id,
      name,
      oldName: old_name,
    });
    return patchNativeUser(this.http, {
      id,
      authMethod,
      comment,
      name,
      password:
        auth_method === AUTH_METHOD_NEW_PASSWORD ? (password ?? '') : undefined,
    });
  }

  async delete({id, inheritorId}: DeleteArguments) {
    log.debug('Deleting user', {id, inheritorId});
    await deleteNativeUser(this.http, id, inheritorId);
  }

  async saveSetting(settingId: string, settingValue: string | number) {
    return putNativeSetting(
      this.http,
      `api/v1/users/current/settings/${settingId}`,
      settingValue,
    );
  }

  async saveTimezone(settingValue: string | number) {
    return putNativeSetting(
      this.http,
      'api/v1/users/current/timezone',
      settingValue,
    );
  }

  async getReportComposerDefaults() {
    const response = await this.getSetting(REPORT_COMPOSER_DEFAULTS_SETTING_ID);
    const {data: setting} = response;
    if (!isDefined(setting?.value)) {
      return response.setData({});
    }

    try {
      return response.setData(JSON.parse(setting.value as string));
    } catch {
      log.warn(
        'Could not parse saved report composer defaults, setting ' +
          'back to default defaults...',
      );
      return response.setData({});
    }
  }

  saveReportComposerDefaults(defaults: Record<string, unknown> = {}) {
    log.debug('Saving report composer defaults', defaults);
    return this.saveSetting(
      REPORT_COMPOSER_DEFAULTS_SETTING_ID,
      JSON.stringify(defaults),
    );
  }

  async renewSession() {
    const response = await fetch(this.http.buildUrl('api/v1/session/renew'), {
      method: 'POST',
      credentials: 'include',
      headers: nativeApiHeaders(this.http),
    });
    if (!response.ok) {
      throw new Error(
        `Native API request failed with status ${response.status}`,
      );
    }
    const payload = (await response.json()) as {
      expires_at?: string | number;
    };
    const expiresAt = parseInt(payload.expires_at);
    return new Response(
      isDefined(expiresAt) ? date.unix(expiresAt) : undefined,
    );
  }

  async changePassword(oldPassword: string, newPassword: string) {
    const response = await fetch(
      this.http.buildUrl('api/v1/users/current/password'),
      {
        method: 'POST',
        credentials: 'include',
        headers: nativeApiHeaders(this.http, true),
        body: JSON.stringify({
          old_password: oldPassword,
          new_password: newPassword,
        }),
      },
    );

    if (!response.ok) {
      throw new Error(
        `Native API request failed with status ${response.status}`,
      );
    }
  }

  async ping() {
    const response = await fetch(this.http.buildUrl('api/v1/session/ping'), {
      method: 'GET',
      credentials: 'include',
      headers: nativeApiHeaders(this.http),
    });
    if (!response.ok) {
      throw new Error(
        `Native API request failed with status ${response.status}`,
      );
    }
    return new Response(undefined);
  }
}

export default UserCommand;
