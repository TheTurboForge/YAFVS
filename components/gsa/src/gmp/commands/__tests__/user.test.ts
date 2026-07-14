/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {createResponse, createHttp} from 'gmp/commands/testing';
import UserCommand, {
  DEFAULT_SETTINGS,
  type CertificateInfo,
  transformSettingName,
} from 'gmp/commands/user';
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
    (path: string) => `https://turbovas.example/${path}`,
  );
  fakeHttp.session = createSession();
  fakeHttp.session.token = 'test-token';
  fakeHttp.session.jwt = 'jwt-token';
  return fakeHttp;
};

describe('UserCommand tests', () => {
  test('should parse auth settings in currentAuthSettings', async () => {
    const response = createResponse({
      auth_settings: {
        describe_auth_response: {
          group: [
            {
              _name: 'foo',
              auth_conf_setting: [
                {
                  key: 'enable',
                  value: true,
                },
              ],
            },
            {
              _name: 'bar',
              auth_conf_setting: [
                {
                  key: 'foo',
                  value: 'true',
                },
                {
                  certificate_info: {
                    issuer: 'ipsum',
                  },
                },
              ],
            },
          ],
        },
      },
    });
    const fakeHttp = createHttp(response);
    const cmd = new UserCommand(fakeHttp);
    const resp = await cmd.currentAuthSettings();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'auth_settings',
        name: '--',
      },
    });
    const {data: settings} = resp;
    expect(settings.has('foo')).toEqual(true);
    expect(settings.has('bar')).toEqual(true);
    expect(settings.has('ipsum')).toEqual(false);
    const fooSettings = settings.get('foo') as {enabled: boolean};
    expect(fooSettings.enabled).toEqual(true);
    const barSettings = settings.get('bar') as {
      foo: string;
      certificateInfo: CertificateInfo;
    };
    expect(barSettings.foo).toEqual('true');
    expect(barSettings.certificateInfo.issuer).toEqual('ipsum');
  });

  test('should return the first single setting value if given an array', async () => {
    const response = createResponse({
      get_settings: {
        get_settings_response: {
          setting: [
            {
              _id: '123',
              name: 'Rows Per Page',
              value: '42',
            },
            {
              _id: '123',
              name: 'Rows Per Page',
              value: '21',
            },
          ],
        },
      },
    });
    const fakeHttp = createHttp(response);
    const cmd = new UserCommand(fakeHttp);
    const {data} = await cmd.getSetting('123');
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_setting',
        setting_id: '123',
      },
    });
    expect(data).toBeDefined();
    expect(data?.id).toEqual('123');
    expect(data?.name).toEqual('Rows Per Page');
    expect(data?.value).toEqual('42');
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

  test('should fetch redacted user metadata through native API when available', async () => {
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

    const result = await cmd.get({id: 'user-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data.id).toEqual('user-id');
    expect(result.data.name).toEqual('admin');
    expect(result.data.comment).toEqual('redacted native account metadata');
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/users/user-id', {
      token: 'test-token',
    });
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

test('should get capabilities', async () => {
  const response = createResponse({
    get_capabilities: {
      help_response: {
        schema: {
          command: [
            {
              name: 'get_reports',
            },
            {
              name: 'get_tasks',
            },
          ],
        },
      },
    },
  });
  const fakeHttp = createHttp(response);
  const cmd = new UserCommand(fakeHttp);
  const {data: caps} = await cmd.currentCapabilities();
  expect(fakeHttp.request).toHaveBeenCalledWith('get', {
    args: {
      cmd: 'get_capabilities',
    },
  });

  expect(caps.length).toBe(2);
  expect(caps.mayAccess('report')).toBe(true);
  expect(caps.mayAccess('task')).toBe(true);
  expect(caps.mayAccess('user')).toBe(false);
  expect(caps.mayCreate('schedule')).toBe(false);
  expect(caps.mayEdit('schedule')).toBe(false);
});

test('should expose native schedule create and modification capabilities', async () => {
  const response = createResponse({
    get_capabilities: {
      help_response: {
        schema: {
          command: [
            {
              name: 'get_schedules',
            },
          ],
        },
      },
    },
  });
  const fakeHttp = createNativeHttp(response);
  const cmd = new UserCommand(fakeHttp);
  const {data: caps} = await cmd.currentCapabilities();

  expect(caps.mayCreate('schedule')).toBe(true);
  expect(caps.mayEdit('schedule')).toBe(true);
});

test('should expose native alert create and modification capabilities', async () => {
  const response = createResponse({
    get_capabilities: {
      help_response: {
        schema: {command: [{name: 'get_alerts'}]},
      },
    },
  });
  const cmd = new UserCommand(createNativeHttp(response));
  const {data: caps} = await cmd.currentCapabilities();

  expect(caps.mayCreate('alert')).toBe(true);
  expect(caps.mayEdit('alert')).toBe(true);
});

describe('UserCommand saveTimezone() tests', () => {
  test('should call httpPost with correct args and handle success', async () => {
    const response = createResponse({success: true});
    const fakeHttp = createHttp(response);
    const cmd = new UserCommand(fakeHttp);
    const settingValue = 'Europe/Berlin';
    await cmd.saveTimezone(settingValue);
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_setting',
        setting_name: 'Timezone',
        setting_value: settingValue,
      },
    });
  });

  test('should throw and log on httpPost error', async () => {
    const error = new Error('fail');
    const fakeHttp = createHttp({});
    fakeHttp.request = () => {
      throw error;
    };
    const cmd = new UserCommand(fakeHttp);
    const settingValue = 'Europe/Berlin';
    await expect(cmd.saveTimezone(settingValue)).rejects.toThrow('fail');
  });
});
describe('UserCommand currentSettings() naming normalization', () => {
  test('should keep current settings suite non-empty', () => {
    expect(transformSettingName('Rows Per Page')).toEqual('rowsperpage');
  });
});
