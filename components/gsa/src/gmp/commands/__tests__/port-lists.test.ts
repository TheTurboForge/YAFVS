/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {PortListsCommand} from 'gmp/commands/port-lists';
import {createEntitiesResponse, createHttp} from 'gmp/commands/testing';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

const createNativeHttp = () => {
  const http = createHttp(undefined) as ReturnType<typeof createHttp> & {
    buildUrl: ReturnType<typeof testing.fn>;
    session: ReturnType<typeof createSession>;
  };

  http.buildUrl = testing.fn(
    (path: string) => `https://turbovas.example/${path}`,
  );
  http.session = createSession();
  http.session.token = 'test-token';
  http.session.jwt = 'jwt-token';

  return http;
};

describe('PortListsCommand', () => {
  test('should use inherited get on non-native http', async () => {
    const response = createEntitiesResponse('port_list', [
      {id: 'p1', name: 'Legacy Port List'},
    ]);
    const http = createHttp(response);
    const command = new PortListsCommand(http);

    const result = await command.get();

    expect(http.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_port_lists',
      },
    });
    expect(result.data[0].id).toEqual('p1');
  });

  test('should fetch port lists through native api when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: 'alpha'},
        items: [
          {
            id: 'p1',
            name: 'Alpha Port List',
            comment: 'Native metadata',
            port_count: {all: 3, tcp: 2, udp: 1},
            port_ranges: [
              {id: 'r1', protocol: 'tcp', start: 1, end: 1000},
            ],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();
    const command = new PortListsCommand(http);

    const result = await command.get({filter: 'first=1 rows=25 search=alpha'});

    expect(http.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('p1');
    expect(result.data[0].name).toEqual('Alpha Port List');
    expect(http.buildUrl).toHaveBeenCalledWith('api/v1/port-lists', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: 'alpha',
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

  test('should fetch all port lists through native api with pagination', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'name',
            filter: 'alpha',
          },
          items: [
            {
              id: 'p1',
              name: 'Alpha Port List',
            },
          ],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 2,
            page_size: 500,
            total: 2,
            sort: 'name',
            filter: 'alpha',
          },
          items: [
            {
              id: 'p2',
              name: 'Beta Port List',
            },
          ],
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();
    const command = new PortListsCommand(http);

    const result = await command.getAll({filter: 'search=alpha'});

    expect(http.request).not.toHaveBeenCalled();
    expect(result.data.map(portList => portList.id)).toEqual(['p1', 'p2']);
    expect(http.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/port-lists', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'alpha',
    });
    expect(http.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/port-lists', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'name',
      filter: 'alpha',
    });
    expect(result.meta.counts.first).toEqual(1);
    expect(result.meta.counts.rows).toEqual(2);
    expect(result.meta.counts.length).toEqual(2);
    expect(result.meta.counts.all).toEqual(2);
    expect(result.meta.counts.filtered).toEqual(2);
  });
});
