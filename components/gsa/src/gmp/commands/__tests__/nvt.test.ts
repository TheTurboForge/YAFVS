/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import NvtCommand from 'gmp/commands/nvt';
import {
  createResponse,
  createHttp,
  createActionResultResponse,
} from 'gmp/commands/testing';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('NvtCommand tests', () => {
  test('should export NVT metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: '1.3.6.1.4.1.25623.1.0.100000',
        name: 'Native NVT',
        family: 'General',
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new NvtCommand(fakeHttp);
    const result = await cmd.export({id: '1.3.6.1.4.1.25623.1.0.100000'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/nvts/1.3.6.1.4.1.25623.1.0.100000/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/nvts/1.3.6.1.4.1.25623.1.0.100000/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: '1.3.6.1.4.1.25623.1.0.100000',
      name: 'Native NVT',
      family: 'General',
    });
  });

  test('should request single NVT through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: '1.2.3',
        oid: '1.2.3',
        name: 'Native NVT',
        default_timeout: '180',
        preferences: [{id: 1, name: 'entry-pref', type: 'entry', value: 'x'}],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new NvtCommand(fakeHttp);
    const resp = await cmd.get({id: '1.2.3'});
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/nvts/1.2.3', {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/nvts/1.2.3',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    const {data: nvt} = resp;
    expect(nvt.id).toEqual('1.2.3');
    expect(nvt.name).toEqual('Native NVT');
    expect(nvt.defaultTimeout).toEqual(180);
    expect(nvt.preferences[0].name).toEqual('entry-pref');
  });

  test('should compose native NVT detail with scan-config preferences', async () => {
    const fetchMock = testing.fn().mockImplementation((url: string) =>
      Promise.resolve({
        json: testing.fn().mockResolvedValue(
          url.endsWith('/scan-config-id')
            ? {
                id: 'scan-config-id',
                preferences: {
                  nvt: [
                    {
                      nvt: {oid: '1.2.3', name: 'Configured NVT'},
                      id: 1,
                      name: 'configured-preference',
                      hr_name: 'Configured preference',
                      type: 'radio',
                      value: 'configured value;other value',
                      default: 'configured default;configured value;fallback',
                    },
                    {
                      nvt: {oid: '1.2.3', name: 'Configured NVT'},
                      id: 0,
                      name: 'timeout',
                      hr_name: 'Timeout (seconds)',
                      type: 'entry',
                      value: '120',
                      default: '300',
                    },
                    {
                      nvt: {oid: '1.2.4', name: 'Other NVT'},
                      id: 2,
                      name: 'other-preference',
                      type: 'entry',
                      value: 'other value',
                    },
                  ],
                },
              }
            : {
                id: '1.2.3',
                oid: '1.2.3',
                name: 'Native NVT',
                default_timeout: '300',
                preferences: [
                  {
                    id: 99,
                    name: 'unconfigured-native-preference',
                    type: 'entry',
                    value: 'native value',
                  },
                ],
              },
        ),
        ok: true,
        status: 200,
      }),
    );
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new NvtCommand(fakeHttp);

    const response = await cmd.getConfigNvt({
      oid: '1.2.3',
      configId: 'scan-config-id',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/nvts/1.2.3', {
      token: 'test-token',
    });
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/scan-configs/scan-config-id',
      {token: 'test-token'},
    );
    expect(response.data.defaultTimeout).toEqual(300);
    expect(response.data.timeout).toEqual(120);
    expect(response.data.preferences).toEqual([
      {
        id: 1,
        name: 'configured-preference',
        hr_name: 'Configured preference',
        type: 'radio',
        value: 'configured value',
        default: 'configured default',
        alt: ['configured default', 'fallback'],
      },
    ]);
  });

  test('should not fall back to GMP when native config NVT loading fails', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'disabled'}}),
      ok: false,
      status: 503,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    const cmd = new NvtCommand(fakeHttp);

    await expect(
      cmd.getConfigNvt({oid: '1.2.3', configId: 'scan-config-id'}),
    ).rejects.toThrow('Native API request failed with status 503');
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should allow to delete a nvt', async () => {
    const response = createActionResultResponse({id: '123'});
    const fakeHttp = createHttp(response);
    const cmd = new NvtCommand(fakeHttp);
    const result = await cmd.delete({id: '123'});
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'delete_info',
        details: '1',
        info_type: 'nvt',
        info_id: '123',
      },
    });
    expect(result).toBeUndefined();
  });
});
