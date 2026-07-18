/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {FiltersCommand} from 'gmp/commands/filters';
import {createHttp} from 'gmp/commands/testing';
import Filter from 'gmp/models/filter';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

const createNativeHttp = () => {
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
  return fakeHttp;
};

describe('FiltersCommand tests', () => {
  test('should fetch filters through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: 'alpha'},
        items: [
          {
            id: 'f1',
            name: 'Alpha Filter',
            comment: 'Native metadata',
            filter_type: 'user',
            term: 'name=Alpha',
            alert_count: 0,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new FiltersCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=alpha'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('f1');
    expect(result.data[0].name).toEqual('Alpha Filter');
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/filters', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: 'alpha',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/filters',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('should fetch all filters through native API with pagination', async () => {
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
              id: 'f1',
              name: 'Alpha Filter',
              filter_type: 'user',
              term: 'name=Alpha',
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
              id: 'f2',
              name: 'Beta Filter',
              filter_type: 'user',
              term: 'name=Beta',
            },
          ],
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new FiltersCommand(fakeHttp);
    const result = await cmd.getAll({filter: 'search=alpha'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data.map(filter => filter.id)).toEqual(['f1', 'f2']);
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/filters', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'alpha',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/filters', {
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

  test('should bulk export selected filters through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'f1', name: 'Alpha'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'f2', name: 'Beta'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new FiltersCommand(fakeHttp);

    const result = await cmd.exportByIds(['f1', 'f2']);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/filters/f1/export',
      {token: 'test-token'},
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/filters/f2/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).filters).toEqual([
      {id: 'f1', name: 'Alpha'},
      {id: 'f2', name: 'Beta'},
    ]);
  });

  test('should bulk export current page filter through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 2,
            page_size: 1,
            total: 3,
            sort: 'name',
            filter: 'alpha',
          },
          items: [{id: 'f2', name: 'Beta', filter_type: 'user'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'f2', name: 'Beta'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new FiltersCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=alpha');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/filters', {
      token: 'test-token',
      page: 2,
      page_size: 1,
      sort: 'name',
      filter: 'alpha',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/filters/f2/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).filters).toEqual([{id: 'f2', name: 'Beta'}]);
  });

  test('should bulk export all filtered filters through native API', async () => {
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
          items: [{id: 'f1', name: 'Alpha', filter_type: 'user'}],
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
          items: [{id: 'f2', name: 'Beta', filter_type: 'user'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'f1', name: 'Alpha'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'f2', name: 'Beta'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new FiltersCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=alpha').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/filters', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'alpha',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/filters', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'name',
      filter: 'alpha',
    });
    expect(JSON.parse(result.data).filters).toEqual([
      {id: 'f1', name: 'Alpha'},
      {id: 'f2', name: 'Beta'},
    ]);
  });
});
