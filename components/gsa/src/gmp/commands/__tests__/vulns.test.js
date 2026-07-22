/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {createAggregatesResponse, createHttp} from 'gmp/commands/testing';
import Filter from 'gmp/models/filter';
import {createSession} from 'gmp/testing';
import {VulnerabilityCommand, VulnerabilitiesCommand} from 'gmp/commands/vulns';

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

describe('VulnerabilityCommand tests', () => {
  test('should export vulnerability metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: '1.3.6.1.4.1.25623.1.0.900001',
        name: 'PostgreSQL vulnerability',
        severity: 7.5,
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new VulnerabilityCommand(fakeHttp);

    const result = await cmd.export({
      id: '1.3.6.1.4.1.25623.1.0.900001',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/vulnerabilities/1.3.6.1.4.1.25623.1.0.900001/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/vulnerabilities/1.3.6.1.4.1.25623.1.0.900001/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: '1.3.6.1.4.1.25623.1.0.900001',
      name: 'PostgreSQL vulnerability',
      severity: 7.5,
    });
  });

});

describe('VulnerabilitiesCommand tests', () => {
  test('fails closed when the native vulnerability list is unavailable', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: false,
      status: 503,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new VulnerabilitiesCommand(fakeHttp);

    await expect(cmd.get()).rejects.toThrow(
      'Native API request failed with status 503',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should fetch vulnerabilities through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 25,
          total: 1,
          sort: '-severity',
          filter: 'postgres',
        },
        items: [
          {
            id: '1.3.6.1.4.1.25623.1.0.900001',
            name: 'PostgreSQL vulnerability',
            family: 'General',
            severity: 7.5,
            qod: 80,
            result_count: 3,
            host_count: 2,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new VulnerabilitiesCommand(fakeHttp);

    const result = await cmd.get({filter: 'first=1 rows=25 search=postgres'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('1.3.6.1.4.1.25623.1.0.900001');
    expect(result.data[0].family).toEqual('General');
    expect(result.data[0].severity).toEqual(7.5);
    expect(result.data[0].results.count).toEqual(3);
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/vulnerabilities', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'severity',
      filter: 'postgres',
    });
  });

  test('fails the selected export without a legacy or partial fallback', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'vuln-1'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 404,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new VulnerabilitiesCommand(fakeHttp);

    await expect(cmd.exportByIds(['vuln-1', 'vuln-2'])).rejects.toThrow(
      'Native API request failed with status 404',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should page through native API for getAll', async () => {
    const responses = [
      {
        page: {page: 1, page_size: 2, total: 3, sort: '-severity', filter: ''},
        items: [
          {
            id: '1.3.6.1.4.1.25623.1.0.900001',
            name: 'PostgreSQL vulnerability',
            family: 'General',
            severity: 7.5,
            qod: 80,
            result_count: 3,
            host_count: 2,
          },
          {
            id: '1.3.6.1.4.1.25623.1.0.900002',
            name: 'SSH vulnerability',
            family: 'General',
            severity: 5,
            qod: 80,
            result_count: 1,
            host_count: 1,
          },
        ],
      },
      {
        page: {page: 2, page_size: 2, total: 3, sort: '-severity', filter: ''},
        items: [
          {
            id: '1.3.6.1.4.1.25623.1.0.900003',
            name: 'TLS vulnerability',
            family: 'General',
            severity: 4,
            qod: 80,
            result_count: 1,
            host_count: 1,
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
    const fakeHttp = createNativeHttp();
    const cmd = new VulnerabilitiesCommand(fakeHttp);

    const result = await cmd.getAll();

    expect(result.data.map(vuln => vuln.id)).toEqual([
      '1.3.6.1.4.1.25623.1.0.900001',
      '1.3.6.1.4.1.25623.1.0.900002',
      '1.3.6.1.4.1.25623.1.0.900003',
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  test('should bulk export selected vulnerabilities through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'vuln-1'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'vuln-2'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new VulnerabilitiesCommand(fakeHttp);

    const result = await cmd.exportByIds(['vuln-1', 'vuln-2']);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/vulnerabilities/vuln-1/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).vulnerabilities).toEqual([
      {id: 'vuln-1'},
      {id: 'vuln-2'},
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
            sort: 'severity',
            filter: 'postgres',
          },
          items: [
            {
              id: 'vuln-2',
              name: 'PostgreSQL vulnerability 2',
              severity: 5,
              qod: 80,
              result_count: 1,
              host_count: 1,
            },
          ],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'vuln-2'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new VulnerabilitiesCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=postgres');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/vulnerabilities',
      {
        token: 'test-token',
        page: 2,
        page_size: 1,
        sort: 'severity',
        filter: 'postgres',
      },
    );
    expect(JSON.parse(result.data).vulnerabilities).toEqual([{id: 'vuln-2'}]);
  });

  test('should bulk export all filtered vulnerabilities through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'severity',
            filter: 'postgres',
          },
          items: [
            {
              id: 'vuln-1',
              name: 'PostgreSQL vulnerability 1',
              severity: 7.5,
              qod: 80,
              result_count: 2,
              host_count: 1,
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
            sort: 'severity',
            filter: 'postgres',
          },
          items: [
            {
              id: 'vuln-2',
              name: 'PostgreSQL vulnerability 2',
              severity: 5,
              qod: 80,
              result_count: 1,
              host_count: 1,
            },
          ],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'vuln-1'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'vuln-2'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new VulnerabilitiesCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=postgres').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/vulnerabilities',
      {
        token: 'test-token',
        page: 1,
        page_size: 500,
        sort: 'severity',
        filter: 'postgres',
      },
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/vulnerabilities',
      {
        token: 'test-token',
        page: 2,
        page_size: 500,
        sort: 'severity',
        filter: 'postgres',
      },
    );
    expect(JSON.parse(result.data).vulnerabilities).toEqual([
      {id: 'vuln-1'},
      {id: 'vuln-2'},
    ]);
  });

  test('should request severity aggregates for vulnerabilities', async () => {
    const response = createAggregatesResponse();
    const fakeHttp = createHttp(response);
    const cmd = new VulnerabilitiesCommand(fakeHttp);

    await cmd.getSeverityAggregates({filter: 'first=1'});

    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        aggregate_type: 'vuln',
        cmd: 'get_aggregate',
        filter: 'first=1',
        group_column: 'severity',
      },
    });
  });

  test('should request host aggregates for vulnerabilities', async () => {
    const response = createAggregatesResponse();
    const fakeHttp = createHttp(response);
    const cmd = new VulnerabilitiesCommand(fakeHttp);

    await cmd.getHostAggregates({filter: 'first=1'});

    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        aggregate_type: 'vuln',
        cmd: 'get_aggregate',
        filter: 'first=1',
        group_column: 'hosts',
      },
    });
  });
});
