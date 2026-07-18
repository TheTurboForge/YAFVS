/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, expect, test, testing} from '@gsa/testing';
import Filter from 'gmp/models/filter';
import {
  nativeReportToModel,
  nativeReportErrorsQueryFromFilter,
  nativeReportTlsCertificatesQueryFromFilter,
  fetchNativeReportPdf,
} from 'gmp/native-api/reports';

const createNativeHttp = () => ({
  buildUrl: testing.fn((path: string) => `https://yafvs.example/${path}`),
  session: {token: 'test-token', jwt: 'jwt-token'},
});

describe('report native API query builders', () => {
  test('should download the native evidence PDF through the same-origin API', async () => {
    const data = new ArrayBuffer(8);
    const fetchMock = testing.fn().mockResolvedValue({
      arrayBuffer: testing.fn().mockResolvedValue(data),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createNativeHttp();

    const reportId = '12345678-1234-1234-1234-123456789abc';
    const result = await fetchNativeReportPdf(gmp, reportId);

    expect(gmp.buildUrl).toHaveBeenCalledWith(
      `api/v1/reports/${reportId}/download`,
      {
        token: 'test-token',
        report_format_id: 'c402cc3e-b531-11e1-9163-406186ea4fc5',
      },
    );
    expect(fetchMock).toHaveBeenCalledWith(
      `https://yafvs.example/api/v1/reports/${reportId}/download`,
      {
        credentials: 'include',
        headers: {
          Accept: 'application/pdf',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result).toBe(data);
  });

  test('should fall back to endpoint defaults for unsupported shared sorts', () => {
    const filter = Filter.fromString(
      'search=postgres rows=25 first=51 sort-reverse=severity',
    );

    expect(nativeReportErrorsQueryFromFilter(filter)).toEqual({
      page: 3,
      pageSize: 25,
      sort: '-created_at',
      filter: 'postgres',
    });
    expect(nativeReportTlsCertificatesQueryFromFilter(filter)).toEqual({
      page: 3,
      pageSize: 25,
      sort: '-not_after',
      filter: 'postgres',
    });
  });

  test('should map supported endpoint-specific sort aliases', () => {
    const errorFilter = Filter.fromString('sort-reverse=nvt');
    const tlsFilter = Filter.fromString('sort=dn');

    expect(nativeReportErrorsQueryFromFilter(errorFilter).sort).toBe(
      '-nvt_oid',
    );
    expect(nativeReportTlsCertificatesQueryFromFilter(tlsFilter).sort).toBe(
      'subject',
    );
  });

  test('should map report detail owner, user tags, and active filter', () => {
    const filter = Filter.fromString(
      'levels=h rows=10 first=1 sort-reverse=severity',
    );
    const report = nativeReportToModel(
      {
        id: 'report-1',
        name: 'Report 1',
        owner: {name: 'native-owner'},
        status: 'Done',
        progress: 87,
        task: {id: 'task-1', name: 'Native Task'},
        result_count: 1,
        vulnerability_count: 1,
        host_count: 1,
        cve_count: 1,
        severity: {
          critical: 0,
          high: 1,
          medium: 0,
          low: 0,
          log: 0,
          false_positive: 0,
        },
        max_severity: 7.5,
        user_tags: [
          {
            id: 'tag-1',
            name: 'Native Tag',
            value: 'native-value',
            comment: 'native comment',
          },
        ],
      },
      filter,
    );

    expect(report.owner?.name).toBe('native-owner');
    expect(report.report?.owner?.name).toBe('native-owner');
    expect(report.report?.task?.progress).toBe(87);
    expect(report.report?.userTags[0]?.name).toBe('Native Tag');
    expect(report.report?.filter?.toFilterString()).toBe(
      filter.toFilterString(),
    );
  });
});
