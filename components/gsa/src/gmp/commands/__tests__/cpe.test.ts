/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import CpeCommand from 'gmp/commands/cpe';
import {createHttp} from 'gmp/commands/testing';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('CpeCommand tests', () => {
  test('should export CPE metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'cpe:/a:vendor:product:1.0',
        name: 'cpe:/a:vendor:product:1.0',
        title: 'Native CPE metadata',
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

    const cmd = new CpeCommand(fakeHttp);
    const result = await cmd.export({id: 'cpe:/a:vendor:product:1.0'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/cpes/cpe%3A%2Fa%3Avendor%3Aproduct%3A1.0',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/cpes/cpe%3A%2Fa%3Avendor%3Aproduct%3A1.0',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: 'cpe:/a:vendor:product:1.0',
      name: 'cpe:/a:vendor:product:1.0',
      title: 'Native CPE metadata',
    });
  });

  test('should get a CPE through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'cpe:/a:vendor:product:1.0',
        name: 'cpe:/a:vendor:product:1.0',
        title: 'Native CPE detail',
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

    const cmd = new CpeCommand(fakeHttp);
    const result = await cmd.get({
      id: 'cpe:/a:vendor:product:1.0',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/cpes/cpe%3A%2Fa%3Avendor%3Aproduct%3A1.0',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/cpes/cpe%3A%2Fa%3Avendor%3Aproduct%3A1.0',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data.id).toEqual('cpe:/a:vendor:product:1.0');
  });

  test('should reject CPE deletion before making an HTTP request', async () => {
    const fakeHttp = createHttp();
    const cmd = new CpeCommand(fakeHttp);

    await expect(cmd.delete({id: '123'})).rejects.toThrow(
      'Catalog entries cannot be deleted through this command',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });
});
