/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import CveCommand from 'gmp/commands/cve';
import {
  createActionResultResponse,
  createHttp,
  createInfoResponse,
} from 'gmp/commands/testing';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('CveCommand tests', () => {
  test('should export CVE metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'CVE-2026-10001',
        name: 'CVE-2026-10001',
        description: 'Native CVE metadata',
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

    const cmd = new CveCommand(fakeHttp);
    const result = await cmd.export({id: 'CVE-2026-10001'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/cves/CVE-2026-10001/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/cves/CVE-2026-10001/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: 'CVE-2026-10001',
      name: 'CVE-2026-10001',
      description: 'Native CVE metadata',
    });
  });

  test('should get a CVE through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'CVE-2026-10001',
        name: 'CVE-2026-10001',
        description: 'Native CVE detail',
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

    const cmd = new CveCommand(fakeHttp);
    const result = await cmd.get({
      id: 'CVE-2026-10001',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/cves/CVE-2026-10001',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/cves/CVE-2026-10001',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data.id).toEqual('CVE-2026-10001');
  });

  test('should allow to clone a cve', async () => {
    const response = createActionResultResponse({id: '456'});
    const fakeHttp = createHttp(response);
    const cmd = new CveCommand(fakeHttp);
    const result = await cmd.clone({id: '123'});
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'clone',
        details: '1',
        info_type: 'cve',
        id: '123',
        resource_type: 'info',
      },
    });
    expect(result.data.id).toEqual('456');
  });

  test('should allow to delete a cve', async () => {
    const response = createActionResultResponse({id: '123'});
    const fakeHttp = createHttp(response);
    const cmd = new CveCommand(fakeHttp);
    const result = await cmd.delete({id: '123'});
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'delete_info',
        details: '1',
        info_type: 'cve',
        info_id: '123',
      },
    });
    expect(result).toBeUndefined();
  });
});
