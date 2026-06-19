/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {fetchNativeOperatingSystems} from 'gmp/native-api/operating-systems';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API operating systems list', () => {
  test('fetches top-level operating systems as inherited OperatingSystem models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: '-latest_severity', filter: ''},
        items: [
          {
            id: 'f3a25f89-2b6c-4e58-92b2-942c686f9342',
            name: 'cpe:/o:example:linux:1.0',
            title: 'Example Linux 1.0',
            latest_severity: 7.5,
            highest_severity: 9.1,
            average_severity: 4.25,
            hosts: 2,
            all_hosts: 3,
            created_at: '2026-06-18T18:00:00Z',
            modified_at: '2026-06-18T20:00:00Z',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeOperatingSystems(gmp, {
      page: 1,
      pageSize: 25,
      sort: '-latest_severity',
      filter: '',
    });

    const os = response.operatingSystems[0];
    expect(response.counts.filtered).toEqual(1);
    expect(os.id).toEqual('f3a25f89-2b6c-4e58-92b2-942c686f9342');
    expect(os.name).toEqual('cpe:/o:example:linux:1.0');
    expect(os.title).toEqual('Example Linux 1.0');
    expect(os.latestSeverity).toEqual(7.5);
    expect(os.highestSeverity).toEqual(9.1);
    expect(os.averageSeverity).toEqual(4.25);
    expect(os.hosts).toEqual(2);
    expect(os.allHosts).toEqual(3);
    expect(os.isInUse()).toEqual(true);
    expect(os.isWritable()).toEqual(false);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/operating-systems', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: '-latest_severity',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/operating-systems',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });
});
