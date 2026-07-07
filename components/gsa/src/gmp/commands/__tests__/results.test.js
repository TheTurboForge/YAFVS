/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {ResultsCommand} from 'gmp/commands/results';
import {
  createHttp,
  createEntitiesResponse,
  createAggregatesResponse,
} from 'gmp/commands/testing';
import Filter, {ALL_FILTER} from 'gmp/models/filter';
import Result from 'gmp/models/result';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

const createNativeHttp = () => {
  const fakeHttp = createHttp(undefined);
  fakeHttp.buildUrl = testing.fn(path => `https://turbovas.example/${path}`);
  fakeHttp.session = createSession();
  fakeHttp.session.token = 'test-token';
  fakeHttp.session.jwt = 'jwt-token';
  return fakeHttp;
};

describe('ResultsCommand tests', () => {
  test('should return all results', async () => {
    const response = createEntitiesResponse('result', [
      {
        _id: '1',
      },
      {
        _id: '2',
      },
    ]);
    const fakeHttp = createHttp(response);
    const cmd = new ResultsCommand(fakeHttp);
    const resp = await cmd.getAll();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_results',
        details: 1,
        filter: ALL_FILTER.toFilterString(),
      },
    });
    const {data} = resp;
    expect(data.length).toEqual(2);
  });

  test('should return results', async () => {
    const response = createEntitiesResponse('result', [
      {
        _id: '1',
      },
      {
        _id: '2',
      },
    ]);
    const fakeHttp = createHttp(response);
    const cmd = new ResultsCommand(fakeHttp);
    const resp = await cmd.get();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_results',
        details: 1,
      },
    });
    const {data} = resp;
    expect(data.length).toEqual(2);
  });

  test('should allow to overwrite details parameter', async () => {
    const response = createEntitiesResponse('result', [
      {
        _id: '1',
      },
      {
        _id: '2',
      },
    ]);

    const fakeHttp = createHttp(response);
    const cmd = new ResultsCommand(fakeHttp);
    await cmd.get({details: 0});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_results',
        details: 0,
      },
    });
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
