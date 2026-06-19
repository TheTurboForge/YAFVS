/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {fetchNativeScanners} from 'gmp/native-api/scanners';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API scanners list', () => {
  test('fetches top-level scanners as inherited Scanner models without credential secrets', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: '08b69003-5fc2-4037-a479-93b440211c73',
            name: 'OpenVAS Default',
            comment: 'scanner metadata only',
            host: '/runtime/run/ospd/ospd-openvas.sock',
            port: 0,
            scanner_type: 2,
            credential: {
              id: '6d799e1f-a81b-4b33-8090-5d4b0ed8ec77',
              name: 'Scanner credential',
            },
            relay_host: '',
            relay_port: 0,
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

    const response = await fetchNativeScanners(gmp, {
      page: 1,
      pageSize: 25,
      sort: 'name',
      filter: '',
    });

    const scanner = response.scanners[0];
    expect(response.counts.filtered).toEqual(1);
    expect(scanner.id).toEqual('08b69003-5fc2-4037-a479-93b440211c73');
    expect(scanner.name).toEqual('OpenVAS Default');
    expect(scanner.comment).toEqual('scanner metadata only');
    expect(scanner.host).toEqual('/runtime/run/ospd/ospd-openvas.sock');
    expect(scanner.hasUnixSocket()).toEqual(true);
    expect(scanner.port).toEqual(0);
    expect(scanner.scannerType).toEqual('2');
    expect(scanner.credential?.id).toEqual('6d799e1f-a81b-4b33-8090-5d4b0ed8ec77');
    expect(scanner.credential?.name).toEqual('Scanner credential');
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/scanners', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scanners',
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
