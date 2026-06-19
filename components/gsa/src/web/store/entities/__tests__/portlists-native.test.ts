/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {
  fetchNativePortList,
  fetchNativePortLists,
} from 'gmp/native-api/port-lists';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API port lists', () => {
  test('fetches top-level port lists as inherited PortList models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: '33d0cd82-57c6-11e1-8ed1-406186ea4fc5',
            name: 'All IANA assigned TCP',
            comment: 'scan all assigned tcp ports',
            predefined: true,
            port_count: {all: 7594, tcp: 7594, udp: 0},
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativePortLists(gmp, {
      page: 1,
      pageSize: 25,
      sort: 'name',
      filter: '',
    });

    const portList = response.portLists[0];
    expect(response.counts.filtered).toEqual(1);
    expect(portList.id).toEqual('33d0cd82-57c6-11e1-8ed1-406186ea4fc5');
    expect(portList.name).toEqual('All IANA assigned TCP');
    expect(portList.comment).toEqual('scan all assigned tcp ports');
    expect(portList.predefined).toEqual(true);
    expect(portList.portCount.all).toEqual(7594);
    expect(portList.portCount.tcp).toEqual(7594);
    expect(portList.portCount.udp).toEqual(0);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/port-lists', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/port-lists',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('fetches port list details with ranges and target backlinks', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: '33d0cd82-57c6-11e1-8ed1-406186ea4fc5',
        name: 'All IANA assigned TCP',
        port_count: {all: 3, tcp: 3, udp: 0},
        port_ranges: [
          {
            id: '2a8ef847-e89b-4b1c-a019-e7ff5d0c4721',
            protocol: 'tcp',
            start: 22,
            end: 24,
          },
        ],
        targets: [
          {
            id: '6b0caa76-6dd0-4e58-aa69-e2974cf85944',
            name: 'Authorized LAN target',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const portList = await fetchNativePortList(
      gmp,
      '33d0cd82-57c6-11e1-8ed1-406186ea4fc5',
    );

    expect(portList.id).toEqual('33d0cd82-57c6-11e1-8ed1-406186ea4fc5');
    expect(portList.portRanges).toHaveLength(1);
    expect(portList.portRanges[0].protocolType).toEqual('tcp');
    expect(portList.portRanges[0].start).toEqual(22);
    expect(portList.portRanges[0].end).toEqual(24);
    expect(portList.targets).toHaveLength(1);
    expect(portList.targets[0].id).toEqual('6b0caa76-6dd0-4e58-aa69-e2974cf85944');
    expect(portList.targets[0].name).toEqual('Authorized LAN target');
  });
});
