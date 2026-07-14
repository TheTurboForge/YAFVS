/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {createHttp} from 'gmp/commands/testing';
import UserCommand, {
  DEFAULT_SETTINGS,
  type CertificateInfo,
  transformSettingName,
} from 'gmp/commands/user';
import date from 'gmp/models/date';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

const createNativeHttp = (response?: Parameters<typeof createHttp>[0]) => {
  const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
    buildUrl: ReturnType<typeof testing.fn>;
    session: ReturnType<typeof createSession>;
  };
  fakeHttp.buildUrl = testing.fn(
    (path: string, params?: Record<string, string>) => {
      const query = params ? `?${new URLSearchParams(params).toString()}` : '';
      return `https://turbovas.example/${path}${query}`;
    },
  );
  fakeHttp.session = createSession();
  fakeHttp.session.token = 'test-token';
  fakeHttp.session.jwt = 'jwt-token';
  return fakeHttp;
};

describe('UserCommand tests', () => {
  test('should parse auth settings in currentAuthSettings', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        ldap: {
          available: true,
          enabled: true,
          host: 'ldap.example',
          auth_dn: 'cn=admin',
          allow_plaintext: true,
          ldaps_only: true,
          certificate: {
            issuer: 'ipsum',
            sha256_fingerprint: 'sha256-value',
          },
        },
        radius: {
          available: true,
          enabled: false,
          host: 'radius.example',
          secret_configured: true,
        },
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new UserCommand(fakeHttp);
    const resp = await cmd.currentAuthSettings();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/authentication-settings',
      expect.objectContaining({method: 'GET'}),
    );
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/authentication-settings',
      undefined,
    );
    const {data: settings} = resp;
    expect(settings.has('method:ldap_connect')).toBe(true);
    expect(settings.has('method:radius_connect')).toBe(true);
    const ldapSettings = settings.get('method:ldap_connect') as {
      allowPlaintext: boolean;
      ldapsOnly: boolean;
      certificateInfo: CertificateInfo;
    };
    expect(ldapSettings.allowPlaintext).toBe(true);
    expect(ldapSettings.ldapsOnly).toBe(true);
    expect(ldapSettings.certificateInfo.issuer).toBe('ipsum');
    expect(ldapSettings.certificateInfo.sha256Fingerprint).toBe('sha256-value');
    expect(settings.get('method:radius_connect')).toMatchObject({
      secretConfigured: true,
      radiuskey: '********',
    });
  });

  test('should clone users through the native management API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'cloned-user'}),
      ok: true,
      status: 201,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new UserCommand(fakeHttp);

    const response = await cmd.clone({id: 'source-user'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/user-management/users/source-user/clone',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(response.data).toEqual({id: 'cloned-user'});
  });

  test('should preserve uncertain native clone outcomes', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          error: {
            code: 'committed_response_unavailable',
            message:
              'The clone committed but its response could not be loaded.',
          },
        }),
        ok: false,
        status: 502,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          error: {
            code: 'mutation_outcome_indeterminate',
            message: 'The clone outcome could not be determined.',
          },
        }),
        ok: false,
        status: 502,
      });
    testing.stubGlobal('fetch', fetchMock);
    const cmd = new UserCommand(createNativeHttp());

    const errors: unknown[] = [];
    for (const id of ['source-user-a', 'source-user-b']) {
      try {
        await cmd.clone({id});
      } catch (error) {
        errors.push(error);
      }
    }

    expect(errors).toEqual([
      expect.objectContaining({
        code: 'committed_response_unavailable',
        message: expect.stringContaining('clone committed'),
      }),
      expect.objectContaining({
        code: 'mutation_outcome_indeterminate',
        message: expect.stringContaining('could not be determined'),
      }),
    ]);
  });

  test('should create, update, and delete users through the management API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'new-user'}),
        ok: true,
        status: 201,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'user-id'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({ok: true, status: 204});
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new UserCommand(fakeHttp);

    await cmd.create({
      auth_method: 'ldap',
      comment: 'directory account',
      name: 'alice',
    });
    await cmd.save({
      id: 'user-id',
      auth_method: 'newpassword',
      comment: 'updated',
      name: 'alice',
      old_name: 'alice',
      password: 'new-secret',
    });
    await cmd.delete({id: 'user-id', inheritorId: 'owner-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'https://turbovas.example/api/v1/user-management/users',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({
          name: 'alice',
          comment: 'directory account',
          auth_method: 'ldap',
        }),
      },
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'https://turbovas.example/api/v1/user-management/users/user-id',
      {
        method: 'PATCH',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({
          name: 'alice',
          comment: 'updated',
          auth_method: 'password',
          password: 'new-secret',
        }),
      },
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      3,
      'https://turbovas.example/api/v1/user-management/users/user-id?inheritor_id=owner-id',
      {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('should send an explicit empty password only for password creation or replacement', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'new-user'}),
        ok: true,
        status: 201,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'user-id'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const cmd = new UserCommand(createNativeHttp());

    await cmd.create({
      auth_method: 'password',
      comment: '',
      name: 'alice',
      password: '',
    });
    await cmd.save({
      id: 'user-id',
      auth_method: 'newpassword',
      comment: '',
      name: 'alice',
      old_name: 'alice',
      password: '',
    });

    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toMatchObject({
      auth_method: 'password',
      password: '',
    });
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toMatchObject({
      auth_method: 'password',
      password: '',
    });
  });

  test('should reject failed user-management writes', async () => {
    testing.stubGlobal(
      'fetch',
      testing.fn().mockResolvedValue({ok: false, status: 409}),
    );
    const cmd = new UserCommand(createNativeHttp());

    await expect(
      cmd.create({
        auth_method: 'password',
        comment: '',
        name: 'alice',
        password: 'secret',
      }),
    ).rejects.toThrow('Native API request failed with status 409');
  });
  test('should ping and renew the GSAD session through native JSON routes', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({status: 'ok'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({expires_at: 1234567890}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new UserCommand(fakeHttp);

    await cmd.ping();
    const renewed = await cmd.renewSession();

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/session/ping');
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/session/renew',
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'https://turbovas.example/api/v1/session/ping',
      {
        method: 'GET',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'https://turbovas.example/api/v1/session/renew',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(renewed.data).toEqual(date.unix(1234567890));
  });

  test('should fetch a current-user setting through the native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: '123',
        name: 'Rows Per Page',
        value: '42',
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new UserCommand(fakeHttp);

    const {data} = await cmd.getSetting('123');

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/users/current/settings/123',
      {token: 'test-token'},
    );
    expect(data).toBeDefined();
    expect(data?.id).toEqual('123');
    expect(data?.name).toEqual('Rows Per Page');
    expect(data?.value).toEqual('42');
  });

  test('should fetch and update current-user settings through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          items: [
            {
              id: 'rows',
              name: 'Rows Per Page',
              value: '42',
            },
            {
              id: 'language',
              name: 'Preferred Language',
              value: 'en',
            },
          ],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValue({
        ok: true,
        status: 204,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new UserCommand(fakeHttp);

    const {data: settings} = await cmd.currentSettings();
    await cmd.saveSetting('rows', 25);
    await cmd.saveTimezone('Europe/Berlin');

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(settings.rowsperpage.value).toEqual('42');
    expect(settings.preferredlanguage.value).toEqual('en');
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'https://turbovas.example/api/v1/users/current/settings?token=test-token',
      {
        method: 'GET',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'https://turbovas.example/api/v1/users/current/settings/rows',
      {
        method: 'PUT',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({value: 25}),
      },
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      3,
      'https://turbovas.example/api/v1/users/current/timezone',
      {
        method: 'PUT',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({value: 'Europe/Berlin'}),
      },
    );
  });

  test('should change password through the native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: true,
      status: 204,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new UserCommand(fakeHttp);

    await cmd.changePassword('oldPassword', 'newPassword');

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/users/current/password',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/users/current/password',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({
          old_password: 'oldPassword',
          new_password: 'newPassword',
        }),
      },
    );
  });

  test('should fetch a user through the management API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'user-id',
        name: 'admin',
        comment: 'account metadata',
        auth_method: 'radius',
        created_at: '2026-07-07T00:00:00Z',
        modified_at: '2026-07-07T01:00:00Z',
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new UserCommand(fakeHttp);

    const result = await cmd.get({id: 'user-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data.id).toEqual('user-id');
    expect(result.data.name).toEqual('admin');
    expect(result.data.comment).toEqual('account metadata');
    expect(result.data.authMethod).toEqual('radius');
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/user-management/users/user-id',
      {
        token: 'test-token',
      },
    );
  });

  test('should export redacted user metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'user-id',
        name: 'admin',
        comment: 'redacted native account metadata',
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new UserCommand(fakeHttp);

    const result = await cmd.export({id: 'user-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/users/user-id', {
      token: 'test-token',
    });
    expect(JSON.parse(result.data)).toEqual({
      id: 'user-id',
      name: 'admin',
      comment: 'redacted native account metadata',
    });
  });
});

describe('UserCommand transformSettingName() function tests', () => {
  test('uses the authoritative SSH default credential setting UUID', () => {
    expect(DEFAULT_SETTINGS.defaultsshcredential).toEqual(
      '6fc56b72-c1cf-451c-a4c4-3a9dc784c3bd',
    );
    expect(DEFAULT_SETTINGS.defaultsshcredential).not.toEqual(
      DEFAULT_SETTINGS.defaultsmbcredential,
    );
  });

  test('should transform string to lower case and remove -', () => {
    const str1 = 'foo';
    const str2 = 'fooBar';
    const str3 = 'foo-bar';
    const str4 = 'foo-Bar';
    expect(transformSettingName(str1)).toEqual('foo');
    expect(transformSettingName(str2)).toEqual('foobar');
    expect(transformSettingName(str3)).toEqual('foobar');
    expect(transformSettingName(str4)).toEqual('foobar');
  });
});

test('should expose complete operator capabilities without a GMP request', async () => {
  const fakeHttp = createHttp();
  const cmd = new UserCommand(fakeHttp);
  const {data: caps} = await cmd.currentCapabilities();

  expect(fakeHttp.request).not.toHaveBeenCalled();
  expect(caps.length).toBe(1);
  expect(caps.mayAccess('report')).toBe(true);
  expect(caps.mayAccess('task')).toBe(true);
  expect(caps.mayAccess('user')).toBe(true);
  expect(caps.mayCreate('schedule')).toBe(true);
  expect(caps.mayEdit('schedule')).toBe(true);
  expect(caps.mayDelete('user')).toBe(true);
});

test('should disable non-retained optional features without a GMP request', async () => {
  const fakeHttp = createHttp();
  const cmd = new UserCommand(fakeHttp);
  const {data: features} = await cmd.currentFeatures();

  expect(fakeHttp.request).not.toHaveBeenCalled();
  expect(features.length).toBe(0);
  expect(features.featureEnabled('ENABLE_OPENVASD')).toBe(false);
  expect(features.featureEnabled('ENABLE_SECURITY_INTELLIGENCE_EXPORT')).toBe(
    false,
  );
});

describe('UserCommand saveTimezone() tests', () => {
  test('should reject a failed native timezone update', async () => {
    testing.stubGlobal(
      'fetch',
      testing.fn().mockResolvedValue({ok: false, status: 400}),
    );
    const fakeHttp = createNativeHttp();
    const cmd = new UserCommand(fakeHttp);

    await expect(cmd.saveTimezone('Europe/Berlin')).rejects.toThrow(
      'Native API request failed with status 400',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });
});
describe('UserCommand currentSettings() naming normalization', () => {
  test('should keep current settings suite non-empty', () => {
    expect(transformSettingName('Rows Per Page')).toEqual('rowsperpage');
  });
});
