/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import DfnCertAdvisoryCommand from 'gmp/commands/dfn-cert-advisory';
import {createHttp} from 'gmp/commands/testing';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('DfnCertAdvisoryCommand tests', () => {
  test('should export DFN-CERT advisory metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'DFN-CERT-2026-2178',
        name: 'DFN-CERT-2026-2178',
        title: 'Native DFN-CERT advisory',
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

    const cmd = new DfnCertAdvisoryCommand(fakeHttp);
    const result = await cmd.export({id: 'DFN-CERT-2026-2178'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/dfn-cert-advisories/DFN-CERT-2026-2178/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/dfn-cert-advisories/DFN-CERT-2026-2178/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: 'DFN-CERT-2026-2178',
      name: 'DFN-CERT-2026-2178',
      title: 'Native DFN-CERT advisory',
    });
  });

  test('should get a dfn cert advisory through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'DFN-CERT-2026-2178',
        name: 'DFN-CERT-2026-2178',
        title: 'Native DFN-CERT advisory',
        rich_detail: {
          links: [{href: 'https://example.test/native', rel: 'alternate'}],
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
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new DfnCertAdvisoryCommand(fakeHttp);
    const result = await cmd.get({
      id: 'DFN-CERT-2026-2178',
    });
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/dfn-cert-advisories/DFN-CERT-2026-2178',
      {token: 'test-token'},
    );
    expect(result.data.id).toEqual('DFN-CERT-2026-2178');
    expect(result.data.advisoryLink).toEqual('https://example.test/native');
  });

  test('should reject DFN-CERT deletion before making an HTTP request', async () => {
    const fakeHttp = createHttp();
    const cmd = new DfnCertAdvisoryCommand(fakeHttp);

    await expect(cmd.delete({id: '123'})).rejects.toThrow(
      'Catalog entries cannot be deleted through this command',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });
});
