/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {OperatingSystemCommand} from 'gmp/commands/os';
import {createPlainResponse, createHttp} from 'gmp/commands/testing';
import Response from 'gmp/http/response';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('OperatingSystemCommand tests', () => {
  test('should include asset_type=os in export of operating system', async () => {
    const content = '<some><xml>exported-data</xml></some>';
    const response = createPlainResponse(content);
    const fakeHttp = createHttp(response);

    const cmd = new OperatingSystemCommand(fakeHttp);
    const cmdResponse = await cmd.export({id: '123'});

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'bulk_export',
        resource_type: 'asset',
        asset_type: 'os',
        bulk_select: 1,
        'bulk_selected:123': 1,
      },
    });
    expect(cmdResponse).toBeInstanceOf(Response);
    expect(cmdResponse.data).toEqual(content);
  });

  test('should export operating system metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        asset: {
          id: 'os-id',
          name: 'Debian GNU/Linux',
          severity: 5.0,
        },
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
      path => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new OperatingSystemCommand(fakeHttp);
    const result = await cmd.export({id: 'os-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/operating-systems/os-id/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/operating-systems/os-id/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      asset: {
        id: 'os-id',
        name: 'Debian GNU/Linux',
        severity: 5.0,
      },
    });
  });

  test('should fall back to GMP when native operating system metadata export fails', async () => {
    const content = '<some><xml>exported-data</xml></some>';
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
      path => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new OperatingSystemCommand(fakeHttp);
    const result = await cmd.export({id: 'os-id'});

    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'bulk_export',
        resource_type: 'asset',
        asset_type: 'os',
        bulk_select: 1,
        'bulk_selected:os-id': 1,
      },
    });
    expect(result.data).toEqual(content);
  });
});
