/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {ReportConfigsCommand} from 'gmp/commands/report-configs';
import {createHttp, createEntitiesResponse} from 'gmp/commands/testing';
import Filter, {ALL_FILTER} from 'gmp/models/filter';
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
    (path: string) => `https://turbovas.example/${path}`,
  );
  fakeHttp.session = createSession();
  fakeHttp.session.token = 'test-token';
  fakeHttp.session.jwt = 'jwt-token';
  return fakeHttp;
};

describe('ReportConfigsCommand tests', () => {
  test('should return all report configs', async () => {
    const response = createEntitiesResponse('report_config', [
      {
        _id: '1',
      },
      {
        _id: '2',
      },
    ]);

    const fakeHttp = createHttp(response);
    const cmd = new ReportConfigsCommand(fakeHttp);
    const resp = await cmd.getAll();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_report_configs',
        filter: ALL_FILTER.toFilterString(),
      },
    });
    const {data} = resp;
    expect(data.length).toEqual(2);
  });

  test('should return report configs', async () => {
    const response = createEntitiesResponse('report_config', [
      {
        _id: '1',
      },
      {
        _id: '2',
      },
    ]);

    const fakeHttp = createHttp(response);

    expect.hasAssertions();

    const cmd = new ReportConfigsCommand(fakeHttp);
    const resp = await cmd.get();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_report_configs',
      },
    });
    const {data} = resp;
    expect(data.length).toEqual(2);
  });

  test('should return filtered report configs', async () => {
    const response = createEntitiesResponse('report_config', [
      {
        _id: '1',
      },
      {
        _id: '2',
      },
    ]);

    const fakeHttp = createHttp(response);
    const cmd = new ReportConfigsCommand(fakeHttp);
    const resp = await cmd.get({filter: 'test filter'});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_report_configs',
        filter: 'test filter',
      },
    });
    const {data} = resp;
    expect(data.length).toEqual(2);
  });

  test('should fetch report configs through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: 'pdf'},
        items: [
          {
            id: 'b7d16778-fb49-4e96-a1d0-5efbc2150f03',
            name: 'PDF Report',
            comment: 'Native metadata',
            owner: {name: 'admin'},
            report_format: {
              id: 'c402cc3e-b531-11e1-9163-406186ea4fc5',
              name: 'PDF',
            },
            writable: true,
            in_use: false,
            orphan: false,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new ReportConfigsCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=pdf'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('b7d16778-fb49-4e96-a1d0-5efbc2150f03');
    expect(result.data[0].name).toEqual('PDF Report');
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/report-configs', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: 'pdf',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/report-configs',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('should use inherited bulk export on non-native http', async () => {
    const fakeHttp = createHttp();
    const cmd = new ReportConfigsCommand(fakeHttp);

    await cmd.exportByIds(['r1', 'r2']);

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'bulk_export',
        resource_type: 'report_config',
        bulk_select: 1,
        'bulk_selected:r1': 1,
        'bulk_selected:r2': 1,
      },
    });
  });

  test('should bulk export selected report configs through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'r1', name: 'PDF'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'r2', name: 'HTML'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ReportConfigsCommand(fakeHttp);

    const result = await cmd.exportByIds(['r1', 'r2']);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/report-configs/r1/export',
      {token: 'test-token'},
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/report-configs/r2/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).report_configs).toEqual([
      {id: 'r1', name: 'PDF'},
      {id: 'r2', name: 'HTML'},
    ]);
  });

  test('should bulk export current page filter through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 1, total: 3, sort: 'name', filter: 'pdf'},
          items: [{id: 'r2', name: 'PDF B'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'r2', name: 'PDF B'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ReportConfigsCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=pdf');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/report-configs',
      {
        token: 'test-token',
        page: 2,
        page_size: 1,
        sort: 'name',
        filter: 'pdf',
      },
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/report-configs/r2/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).report_configs).toEqual([
      {id: 'r2', name: 'PDF B'},
    ]);
  });

  test('should bulk export all filtered report configs through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 1, page_size: 500, total: 2, sort: 'name', filter: 'pdf'},
          items: [{id: 'r1', name: 'PDF A'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 500, total: 2, sort: 'name', filter: 'pdf'},
          items: [{id: 'r2', name: 'PDF B'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'r1', name: 'PDF A'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'r2', name: 'PDF B'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ReportConfigsCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=pdf').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/report-configs',
      {
        token: 'test-token',
        page: 1,
        page_size: 500,
        sort: 'name',
        filter: 'pdf',
      },
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/report-configs',
      {
        token: 'test-token',
        page: 2,
        page_size: 500,
        sort: 'name',
        filter: 'pdf',
      },
    );
    expect(JSON.parse(result.data).report_configs).toEqual([
      {id: 'r1', name: 'PDF A'},
      {id: 'r2', name: 'PDF B'},
    ]);
  });
});
