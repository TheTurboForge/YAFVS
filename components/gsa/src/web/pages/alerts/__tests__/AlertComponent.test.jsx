/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {createSession} from 'gmp/testing';
import {fetchNativeAlertCredentials} from 'web/pages/alerts/AlertComponent';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('AlertComponent native helpers', () => {
  test('should load alert credential choices through the native API', async () => {
    const buildUrl = testing.fn(path => `https://yafvs.example/${path}`);
    const gmp = {
      buildUrl,
      session: createSession({token: 'test-token'}),
    };
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 500, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: 'credential-1',
            name: 'Native credential',
            credential_type: 'up',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);

    const credentials = await fetchNativeAlertCredentials(gmp);

    expect(credentials[0].id).toEqual('credential-1');
    expect(credentials[0].name).toEqual('Native credential');
    expect(credentials[0].credentialType).toEqual('up');
    expect(buildUrl).toHaveBeenCalledWith('api/v1/credentials', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/credentials',
      {
        credentials: 'include',
        headers: {Accept: 'application/json'},
      },
    );
  });
});
