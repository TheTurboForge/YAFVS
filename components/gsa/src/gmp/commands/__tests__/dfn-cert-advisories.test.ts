/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import DfnCertAdvisoriesCommand from 'gmp/commands/dfn-cert-advisories';
import {
  createAggregatesResponse,
  createHttp,
} from 'gmp/commands/testing';
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
    (path: string) => `https://turbovas.example/${path}`,
  );
  fakeHttp.session = createSession();
  fakeHttp.session.token = 'test-token';
  fakeHttp.session.jwt = 'jwt-token';
  return fakeHttp;
};

describe('DfnCertAdvisoriesCommand tests', () => {
  test('should fetch DFN-CERT advisories through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: '-created', filter: 'openssl'},
        items: [
          {
            id: 'dfn-cert-uuid-1',
            name: 'DFN-CERT-2026-001',
            title: 'Example DFN-CERT advisory',
            severity: 8.7,
            cve_refs: 2,
            cves: ['CVE-2026-10001', 'CVE-2026-10002'],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new DfnCertAdvisoriesCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=openssl'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('dfn-cert-uuid-1');
    expect(result.data[0].title).toEqual('Example DFN-CERT advisory');
    expect(result.data[0].severity).toEqual(8.7);
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/dfn-cert-advisories',
      {
        token: 'test-token',
        page: 1,
        page_size: 25,
        sort: 'created',
        filter: 'openssl',
      },
    );
  });

  test('should bulk export selected DFN-CERT advisories through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'dfn1', name: 'DFN-CERT-1'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'dfn2', name: 'DFN-CERT-2'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new DfnCertAdvisoriesCommand(fakeHttp);

    const result = await cmd.exportByIds(['dfn1', 'dfn2']);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/dfn-cert-advisories/dfn1/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).dfncerts).toEqual([
      {id: 'dfn1', name: 'DFN-CERT-1'},
      {id: 'dfn2', name: 'DFN-CERT-2'},
    ]);
  });

  test('should bulk export current page filter through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 1, total: 3, sort: 'created', filter: 'openssl'},
          items: [{id: 'dfn2'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'dfn2', name: 'DFN-CERT-2'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new DfnCertAdvisoriesCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=openssl');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/dfn-cert-advisories',
      {
        token: 'test-token',
        page: 2,
        page_size: 1,
        sort: 'created',
        filter: 'openssl',
      },
    );
    expect(JSON.parse(result.data).dfncerts).toEqual([
      {id: 'dfn2', name: 'DFN-CERT-2'},
    ]);
  });

  test('should bulk export all filtered DFN-CERT advisories through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 1, page_size: 500, total: 2, sort: 'created', filter: 'openssl'},
          items: [{id: 'dfn1'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 500, total: 2, sort: 'created', filter: 'openssl'},
          items: [{id: 'dfn2'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'dfn1', name: 'DFN-CERT-1'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'dfn2', name: 'DFN-CERT-2'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new DfnCertAdvisoriesCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=openssl').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/dfn-cert-advisories',
      {
        token: 'test-token',
        page: 1,
        page_size: 500,
        sort: 'created',
        filter: 'openssl',
      },
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/dfn-cert-advisories',
      {
        token: 'test-token',
        page: 2,
        page_size: 500,
        sort: 'created',
        filter: 'openssl',
      },
    );
    expect(JSON.parse(result.data).dfncerts).toEqual([
      {id: 'dfn1', name: 'DFN-CERT-1'},
      {id: 'dfn2', name: 'DFN-CERT-2'},
    ]);
  });

  test('should fetch severity aggregates', async () => {
    const response = createAggregatesResponse({});
    const fakeHttp = createHttp(response);

    const cmd = new DfnCertAdvisoriesCommand(fakeHttp);
    const result = await cmd.getSeverityAggregates();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_aggregate',
        aggregate_type: 'dfn_cert_adv',
        group_column: 'severity',
        info_type: 'dfn_cert_adv',
      },
    });
    expect(result.data).toEqual({groups: []});
  });

  test('should fetch created aggregates', async () => {
    const response = createAggregatesResponse({});
    const fakeHttp = createHttp(response);

    const cmd = new DfnCertAdvisoriesCommand(fakeHttp);
    const result = await cmd.getCreatedAggregates();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_aggregate',
        aggregate_type: 'dfn_cert_adv',
        group_column: 'created',
        info_type: 'dfn_cert_adv',
      },
    });
    expect(result.data).toEqual({groups: []});
  });
});
