/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {
  fetchNativeScopeReportCves,
  fetchNativeScopeReportErrors,
  fetchNativeScopeReportHosts,
  fetchNativeScopeReportPorts,
  fetchNativeScopeReportResults,
} from 'gmp/native-api/scope-report-collections';

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

describe('native API scope report evidence collections', () => {
  test('fetches paginated scope-report hosts through the same-origin native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 2,
          page_size: 25,
          total: 42,
          sort: '-result_count',
          filter: 'linux',
        },
        items: [
          {
            host: '192.0.2.10',
            scope_membership: 'member',
            source_report_count: 2,
            result_count: 9,
            vulnerability_count: 3,
            authenticated_scan_state: 'authenticated',
            source_report_ids: ['report-1', 'report-2'],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const collection = await fetchNativeScopeReportHosts(
      gmp,
      'scope-1',
      'scope-report-1',
      {page: 2, pageSize: 25, sort: '-result_count', filter: 'linux'},
    );

    expect(collection.page.total).toEqual(42);
    expect(collection.items[0].host).toEqual('192.0.2.10');
    expect(collection.items[0].scopeMembership).toEqual('member');
    expect(collection.items[0].authenticatedScanState).toEqual('authenticated');
    expect(collection.items[0].sourceReportIds).toEqual([
      'report-1',
      'report-2',
    ]);
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/scopes/scope-1/reports/scope-report-1/hosts',
      {
        token: 'test-token',
        page: 2,
        page_size: 25,
        sort: '-result_count',
        filter: 'linux',
      },
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/scopes/scope-1/reports/scope-report-1/hosts',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('fetches result rows with raw evidence links', async () => {
    testing.stubGlobal(
      'fetch',
      testing.fn().mockResolvedValue({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 25,
            total: 1,
            sort: '-severity',
            filter: '',
          },
          items: [
            {
              id: 'result-1',
              host: '192.0.2.10',
              port: '22/tcp',
              nvt_oid: '1.3.6.1.4.1.25623.1.0.1',
              name: 'Example finding',
              severity: 7.5,
              qod: 80,
              created_at: '2026-06-17T10:00:00Z',
              source_report_id: 'raw-report-1',
              raw_evidence_href: '/result/result-1',
            },
          ],
        }),
        ok: true,
        status: 200,
      }),
    );
    const gmp = createGmp();

    const collection = await fetchNativeScopeReportResults(
      gmp,
      'scope-1',
      'scope-report-1',
      {page: 1, pageSize: 25, sort: '-severity'},
    );

    expect(collection.items[0].name).toEqual('Example finding');
    expect(collection.items[0].severity).toEqual(7.5);
    expect(collection.items[0].rawEvidenceHref).toEqual('/result/result-1');
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/scopes/scope-1/reports/scope-report-1/results',
      {
        token: 'test-token',
        page: 1,
        page_size: 25,
        sort: '-severity',
        filter: undefined,
      },
    );
  });

  test('fetches port rows and maps aggregate fields', async () => {
    testing.stubGlobal(
      'fetch',
      testing.fn().mockResolvedValue({
        json: testing.fn().mockResolvedValue({
          page: {page: 1, page_size: 25, total: 1, sort: 'port', filter: ''},
          items: [
            {
              port: '443/tcp',
              protocol: 'tcp',
              host_count: 3,
              result_count: 8,
              vulnerability_count: 2,
              max_severity: 7.5,
              source_report_ids: ['report-1', 'report-2'],
            },
          ],
        }),
        ok: true,
        status: 200,
      }),
    );
    const gmp = createGmp();

    const collection = await fetchNativeScopeReportPorts(
      gmp,
      'scope-1',
      'scope-report-1',
      {page: 1, pageSize: 25, sort: 'port'},
    );

    expect(collection.items[0].port).toEqual('443/tcp');
    expect(collection.items[0].protocol).toEqual('tcp');
    expect(collection.items[0].hostCount).toEqual(3);
    expect(collection.items[0].maxSeverity).toEqual(7.5);
    expect(collection.items[0].sourceReportIds).toEqual([
      'report-1',
      'report-2',
    ]);
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/scopes/scope-1/reports/scope-report-1/ports',
      {
        token: 'test-token',
        page: 1,
        page_size: 25,
        sort: 'port',
        filter: undefined,
      },
    );
  });

  test('fetches CVE rows and maps aggregate fields', async () => {
    testing.stubGlobal(
      'fetch',
      testing.fn().mockResolvedValue({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 25,
            total: 1,
            sort: '-max_severity',
            filter: '',
          },
          items: [
            {
              id: 'CVE-2026-0001',
              affected_system_count: 4,
              result_count: 7,
              max_severity: 9.8,
              source_report_ids: ['report-1'],
            },
          ],
        }),
        ok: true,
        status: 200,
      }),
    );
    const gmp = createGmp();

    const collection = await fetchNativeScopeReportCves(
      gmp,
      'scope-1',
      'scope-report-1',
      {page: 1, pageSize: 25, sort: '-max_severity'},
    );

    expect(collection.items[0].id).toEqual('CVE-2026-0001');
    expect(collection.items[0].affectedSystemCount).toEqual(4);
    expect(collection.items[0].maxSeverity).toEqual(9.8);
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/scopes/scope-1/reports/scope-report-1/cves',
      {
        token: 'test-token',
        page: 1,
        page_size: 25,
        sort: '-max_severity',
        filter: undefined,
      },
    );
  });

  test('fetches error-message rows with raw report provenance', async () => {
    testing.stubGlobal(
      'fetch',
      testing.fn().mockResolvedValue({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 25,
            total: 1,
            sort: '-created_at',
            filter: '',
          },
          items: [
            {
              id: 'result-1',
              host: '192.0.2.10',
              port: '22/tcp',
              nvt_oid: '1.3.6.1.4.1.25623.1.0.1',
              description: 'Example scanner error',
              source_report_id: 'raw-report-1',
              created_at: '2026-06-17T10:00:00Z',
            },
          ],
        }),
        ok: true,
        status: 200,
      }),
    );
    const gmp = createGmp();

    const collection = await fetchNativeScopeReportErrors(
      gmp,
      'scope-1',
      'scope-report-1',
      {page: 1, pageSize: 25, sort: '-created_at'},
    );

    expect(collection.items[0].description).toEqual('Example scanner error');
    expect(collection.items[0].sourceReportId).toEqual('raw-report-1');
    expect(collection.items[0].createdAt).toEqual('2026-06-17T10:00:00Z');
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/scopes/scope-1/reports/scope-report-1/errors',
      {
        token: 'test-token',
        page: 1,
        page_size: 25,
        sort: '-created_at',
        filter: undefined,
      },
    );
  });

  test('raises a clear error for failed collection responses', async () => {
    testing.stubGlobal(
      'fetch',
      testing.fn().mockResolvedValue({ok: false, status: 403}),
    );
    const gmp = createGmp();

    await expect(
      fetchNativeScopeReportHosts(gmp, 'scope-1', 'scope-report-1', {
        page: 1,
        pageSize: 25,
        sort: 'host',
      }),
    ).rejects.toThrow('Native API request failed with status 403');
  });
});
