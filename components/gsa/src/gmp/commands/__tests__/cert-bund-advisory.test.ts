/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import CertBundAdvisoryCommand from 'gmp/commands/cert-bund-advisory';
import {createActionResultResponse, createHttp} from 'gmp/commands/testing';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('CertBundAdvisoryCommand tests', () => {
  test('should export CERT-Bund advisory metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'CB-K26-0123',
        name: 'CB-K26-0123',
        title: 'Native CERT-Bund advisory',
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

    const cmd = new CertBundAdvisoryCommand(fakeHttp);
    const result = await cmd.export({id: 'CB-K26-0123'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/cert-bund-advisories/CB-K26-0123/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/cert-bund-advisories/CB-K26-0123/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: 'CB-K26-0123',
      name: 'CB-K26-0123',
      title: 'Native CERT-Bund advisory',
    });
  });

  test('should get a cert bund advisory through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'CB-K26-0123',
        name: 'CB-K26-0123',
        title: 'Native CERT-Bund advisory',
        rich_detail: {
          description: ['Native detail'],
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
    const cmd = new CertBundAdvisoryCommand(fakeHttp);
    const result = await cmd.get({
      id: 'CB-K26-0123',
    });
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/cert-bund-advisories/CB-K26-0123',
      {token: 'test-token'},
    );
    expect(result.data.id).toEqual('CB-K26-0123');
    expect(result.data.description).toEqual(['Native detail']);
  });

  test('should allow to clone a cert bund advisory', async () => {
    const response = createActionResultResponse({id: '456'});
    const fakeHttp = createHttp(response);
    const cmd = new CertBundAdvisoryCommand(fakeHttp);
    const result = await cmd.clone({id: '123'});
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'clone',
        details: '1',
        info_type: 'cert_bund_adv',
        id: '123',
        resource_type: 'info',
      },
    });
    expect(result.data.id).toEqual('456');
  });

  test('should allow to delete a cert bund advisory', async () => {
    const response = createActionResultResponse({id: '123'});
    const fakeHttp = createHttp(response);
    const cmd = new CertBundAdvisoryCommand(fakeHttp);
    const result = await cmd.delete({id: '123'});
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'delete_info',
        details: '1',
        info_type: 'cert_bund_adv',
        info_id: '123',
      },
    });
    expect(result).toBeUndefined();
  });
});
