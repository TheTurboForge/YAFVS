/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {rendererWith, waitFor} from 'web/testing';
import CollectionCounts from 'gmp/collection/collection-counts';
import Filter from 'gmp/models/filter';
import {createSession} from 'gmp/testing';
import useGetReportCves from 'web/hooks/use-query/report-cves';
import useGetReportTlsCertificates from 'web/hooks/use-query/report-tls-certificates';

const reportId = 'report-123';
const filter = Filter.fromString(
  'search=openssl rows=25 first=51 sort-reverse=severity',
);

const buildUrl = (path: string, params?: Record<string, unknown>) => {
  const query = new URLSearchParams();
  Object.entries(params ?? {}).forEach(([key, value]) => {
    if (value !== undefined) {
      query.set(key, String(value));
    }
  });
  return `https://turbovas.example/${path}${
    query.size > 0 ? `?${query.toString()}` : ''
  }`;
};

const createNativeGmp = () => ({
  buildUrl: testing.fn(buildUrl),
  session: createSession({token: 'test-token'}),
  settings: {
    reloadInterval: 15000,
    reloadIntervalActive: 3000,
    reloadIntervalInactive: 60000,
  },
  reportcves: {
    get: testing.fn(),
  },
  reporttlscertificates: {
    get: testing.fn(),
  },
});

const createLegacyGmp = () => ({
  session: createSession({token: 'test-token'}),
  settings: {
    reloadInterval: 15000,
    reloadIntervalActive: 3000,
    reloadIntervalInactive: 60000,
  },
  reportcves: {
    get: testing.fn().mockResolvedValue({
      data: [],
      meta: {
        filter,
        counts: new CollectionCounts({all: 3, filtered: 3}),
      },
    }),
  },
  reporttlscertificates: {
    get: testing.fn().mockResolvedValue({
      data: [],
      meta: {
        filter,
        counts: new CollectionCounts({all: 4, filtered: 4}),
      },
    }),
  },
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('report detail count preload hooks', () => {
  test('should preload report CVE counts through native page totals', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 1,
          total: 9,
          sort: '-max_severity',
          filter: 'openssl',
        },
        items: [],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createNativeGmp();
    const {renderHook} = rendererWith({gmp, router: true});

    const {result} = renderHook(() => useGetReportCves({reportId, filter}));

    await waitFor(() => {
      expect(result.current.data?.entitiesCounts.filtered).toBe(9);
    });
    expect(result.current.data?.entitiesCounts.all).toBe(9);
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      `api/v1/reports/${reportId}/cves`,
      expect.objectContaining({
        token: 'test-token',
        page: 1,
        page_size: 1,
        sort: '-max_severity',
        filter: 'openssl',
      }),
    );
    expect(gmp.reportcves.get).not.toHaveBeenCalled();
  });

  test('should preload report TLS Certificate counts through native page totals', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 1,
          total: 6,
          sort: '-not_after',
          filter: 'openssl',
        },
        items: [],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createNativeGmp();
    const {renderHook} = rendererWith({gmp, router: true});

    const {result} = renderHook(() =>
      useGetReportTlsCertificates({reportId, filter}),
    );

    await waitFor(() => {
      expect(result.current.data?.entitiesCounts.filtered).toBe(6);
    });
    expect(result.current.data?.entitiesCounts.all).toBe(6);
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      `api/v1/reports/${reportId}/tls-certificates`,
      expect.objectContaining({
        token: 'test-token',
        page: 1,
        page_size: 1,
        sort: '-not_after',
        filter: 'openssl',
      }),
    );
    expect(gmp.reporttlscertificates.get).not.toHaveBeenCalled();
  });

  test('should fall back to inherited report CVE hook without native URL builder', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createLegacyGmp();
    const {renderHook} = rendererWith({gmp, router: true});

    const {result} = renderHook(() => useGetReportCves({reportId, filter}));

    await waitFor(() => {
      expect(result.current.data?.entitiesCounts.filtered).toBe(3);
    });
    expect(gmp.reportcves.get).toHaveBeenCalledWith({
      report_id: reportId,
      filter,
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('should fall back to inherited report TLS Certificate hook without native URL builder', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createLegacyGmp();
    const {renderHook} = rendererWith({gmp, router: true});

    const {result} = renderHook(() =>
      useGetReportTlsCertificates({reportId, filter}),
    );

    await waitFor(() => {
      expect(result.current.data?.entitiesCounts.filtered).toBe(4);
    });
    expect(gmp.reporttlscertificates.get).toHaveBeenCalledWith({
      report_id: reportId,
      filter,
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
