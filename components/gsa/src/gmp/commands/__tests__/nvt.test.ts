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
  createPlainResponse,
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
      (path: string) => `https://turbovas.example/${path}`,
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
      'https://turbovas.example/api/v1/nvts/1.3.6.1.4.1.25623.1.0.100000/export',
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

  test('should fall back to GMP when native NVT metadata export fails', async () => {
    const content = '<some><xml>exported-nvt</xml></some>';
    const response = createPlainResponse(content);
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'disabled'}}),
      ok: false,
      status: 503,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new NvtCommand(fakeHttp);
    const result = await cmd.export({id: '1.3.6.1.4.1.25623.1.0.100000'});

    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'bulk_export',
        details: '1',
        info_type: 'nvt',
        resource_type: 'info',
        bulk_select: 1,
        'bulk_selected:1.3.6.1.4.1.25623.1.0.100000': 1,
      },
    });
    expect(result.data).toEqual(content);
  });

  test('should request single nvt', async () => {
    const response = createResponse({
      get_info: {
        get_info_response: {
          info: [
            {
              nvt: {
                _oid: '1.2.3',
              },
            },
          ],
        },
      },
    });
    const fakeHttp = createHttp(response);
    const cmd = new NvtCommand(fakeHttp);
    const resp = await cmd.get({id: '1.2.3'});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_info',
        info_id: '1.2.3',
        details: '1',
        info_type: 'nvt',
      },
    });
    const {data: nvt} = resp;
    expect(nvt.id).toEqual('1.2.3');
  });

  test('should return config nvt', async () => {
    const response = createResponse({
      get_config_nvt_response: {
        get_nvts_response: {
          nvt: {
            _oid: '1.2.3',
          },
        },
      },
    });
    const fakeHttp = createHttp(response);
    const cmd = new NvtCommand(fakeHttp);
    const resp = await cmd.getConfigNvt({oid: '1.2.3', configId: 'c1'});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_config_nvt',
        config_id: 'c1',
        oid: '1.2.3',
      },
    });
    const {data: nvt} = resp;
    expect(nvt.id).toEqual('1.2.3');
  });

  test('should allow to clone a nvt', async () => {
    const response = createActionResultResponse({id: '456'});
    const fakeHttp = createHttp(response);
    const cmd = new NvtCommand(fakeHttp);
    const result = await cmd.clone({id: '123'});
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'clone',
        details: '1',
        info_type: 'nvt',
        id: '123',
        resource_type: 'info',
      },
    });
    expect(result.data.id).toEqual('456');
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
