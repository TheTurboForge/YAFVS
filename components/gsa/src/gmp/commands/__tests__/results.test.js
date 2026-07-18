/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {ResultsCommand} from 'gmp/commands/results';
import {createHttp, createAggregatesResponse} from 'gmp/commands/testing';
import Filter, {ALL_FILTER} from 'gmp/models/filter';
import Result from 'gmp/models/result';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

const createNativeHttp = () => {
  const fakeHttp = createHttp(undefined);
  fakeHttp.buildUrl = testing.fn(path => `https://yafvs.example/${path}`);
  fakeHttp.session = createSession();
  fakeHttp.session.token = 'test-token';
  fakeHttp.session.jwt = 'jwt-token';
  return fakeHttp;
};

describe('ResultsCommand tests', () => {
  test('should fetch results through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'severity', filter: ''},
        items: [
          {
            id: 'result-1',
            name: 'Native result',
            vulnerability: {id: 'vuln-1', name: 'CVE-2026-0001'},
            host: {id: 'host-1', name: 'web.example'},
            severity: 5.5,
            threat: 'Medium',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ResultsCommand(fakeHttp);

    const resp = await cmd.get();

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/results', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'severity',
      filter: '',
    });
    expect(resp.data[0].id).toEqual('result-1');
    expect(resp.meta.counts.filtered).toEqual(1);
  });

  test('should fetch explicit summary-only result reads through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1},
        items: [
          {
            id: 'result-id',
            host: '192.0.2.1',
            port: '443/tcp',
            nvt_oid: '1.3.6.1.4.1.25623.1.0.1',
            name: 'Native result',
            severity: 7.5,
            qod: 80,
            source_report_id: 'report-id',
            raw_evidence_href: '/reports/report-id/results/result-id',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined);
    fakeHttp.buildUrl = testing.fn(path => `https://yafvs.example/${path}`);
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new ResultsCommand(fakeHttp);

    const result = await cmd.get({details: 0});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/results', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'severity',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/results',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data[0].id).toEqual('result-id');
  });

  test('should aggregate Description Word Counts', async () => {
    const response = createAggregatesResponse();
    const fakeHttp = createHttp(response);
    const cmd = new ResultsCommand(fakeHttp);
    await cmd.getDescriptionWordCountsAggregates();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_aggregate',
        aggregate_type: 'result',
        group_column: 'description',
        aggregate_mode: 'word_counts',
        max_groups: '250',
      },
    });
  });

  test('should aggregate word counts', async () => {
    const response = createAggregatesResponse();
    const fakeHttp = createHttp(response);
    const cmd = new ResultsCommand(fakeHttp);
    await cmd.getWordCountsAggregates();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_aggregate',
        aggregate_type: 'result',
        group_column: 'vulnerability',
        aggregate_mode: 'word_counts',
        max_groups: '250',
      },
    });
  });

  test('should aggregate severities', async () => {
    const response = createAggregatesResponse();
    const fakeHttp = createHttp(response);
    const cmd = new ResultsCommand(fakeHttp);
    await cmd.getSeverityAggregates();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_aggregate',
        aggregate_type: 'result',
        group_column: 'severity',
      },
    });
  });

  test('should bulk export selected results through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'result-1', name: 'One'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'result-2', name: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ResultsCommand(fakeHttp);

    const result = await cmd.export([
      new Result({id: 'result-1'}),
      new Result({id: 'result-2'}),
    ]);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/results/result-1/export',
      {token: 'test-token'},
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/results/result-2/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).results).toEqual([
      {id: 'result-1', name: 'One'},
      {id: 'result-2', name: 'Two'},
    ]);
  });

  test('should bulk export current page results through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 2,
            page_size: 1,
            total: 3,
            sort: 'severity',
            filter: 'web',
          },
          items: [{id: 'result-2', name: 'Two'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'result-2', name: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ResultsCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=web');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/results', {
      token: 'test-token',
      page: 2,
      page_size: 1,
      sort: 'severity',
      filter: 'web',
    });
    expect(JSON.parse(result.data).results).toEqual([
      {id: 'result-2', name: 'Two'},
    ]);
  });

  test('should bulk export all filtered results through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'severity',
            filter: 'web',
          },
          items: [{id: 'result-1', name: 'One'}],
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
            sort: 'severity',
            filter: 'web',
          },
          items: [{id: 'result-2', name: 'Two'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'result-1', name: 'One'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'result-2', name: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ResultsCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=web').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/results', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'severity',
      filter: 'web',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/results', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'severity',
      filter: 'web',
    });
    expect(JSON.parse(result.data).results).toEqual([
      {id: 'result-1', name: 'One'},
      {id: 'result-2', name: 'Two'},
    ]);
  });
});
