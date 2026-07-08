/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import ReportsCommand from 'gmp/commands/reports';
import {createHttp} from 'gmp/commands/testing';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('ReportsCommand tests', () => {
  test('should fetch reports through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 25,
          total: 1,
          sort: '-creation_time',
          filter: 'done',
        },
        items: [
          {
            id: 'report-1',
            name: 'Native report',
            status: 'Done',
            creation_time: '2026-06-14T06:27:42Z',
            result_count: 7,
            vulnerability_count: 3,
            host_count: 1,
            max_severity: 8.2,
            severity: {
              critical: 1,
              high: 2,
              medium: 3,
              low: 1,
              log: 0,
              false_positive: 0,
            },
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined);
    fakeHttp.buildUrl = testing.fn(
      path => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new ReportsCommand(fakeHttp);

    const result = await cmd.get({filter: 'first=1 rows=25 search=done'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('report-1');
    expect(result.data[0].name).toEqual('Native report');
    expect(result.meta.counts.filtered).toEqual(1);
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/reports', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'creation_time',
      filter: 'done',
    });
  });

  test('should page through native API for getAll', async () => {
    const responses = [
      {
        page: {page: 1, page_size: 500, total: 2, sort: '-creation_time', filter: ''},
        items: [
          {
            id: 'report-1',
            name: 'One',
            status: 'Done',
            result_count: 1,
            vulnerability_count: 1,
            host_count: 1,
            max_severity: 5,
            severity: {critical: 0, high: 0, medium: 1, low: 0, log: 0, false_positive: 0},
          },
        ],
      },
      {
        page: {page: 2, page_size: 500, total: 2, sort: '-creation_time', filter: ''},
        items: [
          {
            id: 'report-2',
            name: 'Two',
            status: 'Done',
            result_count: 2,
            vulnerability_count: 2,
            host_count: 1,
            max_severity: 7,
            severity: {critical: 0, high: 1, medium: 1, low: 0, log: 0, false_positive: 0},
          },
        ],
      },
    ];
    const fetchMock = testing.fn().mockImplementation(() =>
      Promise.resolve({
        json: testing.fn().mockResolvedValue(responses.shift()),
        ok: true,
        status: 200,
      }),
    );
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined);
    fakeHttp.buildUrl = testing.fn(
      path => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new ReportsCommand(fakeHttp);

    const result = await cmd.getAll();

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data.map(report => report.id)).toEqual(['report-1', 'report-2']);
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/reports', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'creation_time',
      filter: '',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/reports', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'creation_time',
      filter: '',
    });
  });
});
