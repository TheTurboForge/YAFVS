/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import Filter from 'gmp/models/filter';
import {
  fetchNativePortList,
  fetchNativePortLists,
} from 'gmp/native-api/port-lists';
import {loadEntities, loadEntity} from 'web/store/entities/portlists';
import {createState} from 'web/store/entities/utils/testing';
import {filterIdentifier} from 'web/store/utils';

const createGmp = ({
  jwt,
  token = 'test-token',
}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://yafvs.example/${path}`),
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
      'https://yafvs.example/api/v1/port-lists',
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
        user_tags: [
          {
            id: '8afbe92e-f808-447c-9399-1492f3f9ef3f',
            name: 'Native tag',
            value: 'true',
            comment: 'Native port list tag',
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
    expect(portList.targets[0].id).toEqual(
      '6b0caa76-6dd0-4e58-aa69-e2974cf85944',
    );
    expect(portList.targets[0].name).toEqual('Authorized LAN target');
    expect(portList.userTags).toHaveLength(1);
    expect(portList.userTags[0].id).toEqual(
      '8afbe92e-f808-447c-9399-1492f3f9ef3f',
    );
    expect(portList.userTags[0].name).toEqual('Native tag');
    expect(portList.userTags[0].value).toEqual('true');
    expect(portList.userTags[0].comment).toEqual('Native port list tag');
  });

  test('loads the port-list store through same-origin native API', async () => {
    const filter = Filter.fromString('first=1 rows=10 sort=name');
    const rootState = createState('portlist', {
      isLoading: {
        [filterIdentifier(filter)]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 10, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: '33d0cd82-57c6-11e1-8ed1-406186ea4fc5',
            name: 'All IANA assigned TCP',
            port_count: {all: 7594, tcp: 7594, udp: 0},
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();

    await loadEntities(gmp)(filter)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/port-lists', {
      token: 'test-token',
      page: 1,
      page_size: 10,
      sort: 'name',
      filter: '',
    });
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITIES_LOADING_SUCCESS');
    expect(successAction.counts.filtered).toEqual(1);
    expect(successAction.data[0].name).toEqual('All IANA assigned TCP');
    expect(successAction.data[0].portCount.tcp).toEqual(7594);
  });

  test('loads port-list detail store entries through same-origin native API', async () => {
    const id = '33d0cd82-57c6-11e1-8ed1-406186ea4fc5';
    const rootState = createState('portlist', {
      isLoading: {
        [id]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id,
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
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();

    await loadEntity(gmp)(id)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/port-lists/33d0cd82-57c6-11e1-8ed1-406186ea4fc5',
      {token: 'test-token'},
    );
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITY_LOADING_SUCCESS');
    expect(successAction.data.name).toEqual('All IANA assigned TCP');
    expect(successAction.data.portRanges).toHaveLength(1);
  });
});
