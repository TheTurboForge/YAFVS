/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, expect, test} from '@gsa/testing';
import Filter from 'gmp/models/filter';
import {
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
});
