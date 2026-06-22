/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, expect, test} from '@gsa/testing';
import Filter from 'gmp/models/filter';
import {
  nativeReportToModel,
  nativeReportErrorsQueryFromFilter,
  nativeReportTlsCertificatesQueryFromFilter,
} from 'gmp/native-api/reports';

describe('report native API query builders', () => {
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
    expect(report.report?.userTags[0]?.name).toBe('Native Tag');
    expect(report.report?.filter?.toFilterString()).toBe(
      filter.toFilterString(),
    );
  });
});
