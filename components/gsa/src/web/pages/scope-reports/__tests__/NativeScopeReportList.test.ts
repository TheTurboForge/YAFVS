/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {
  fetchNativeScopeReport,
  fetchNativeScopeReports,
} from 'gmp/native-api/scope-reports';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API scope report list', () => {
  test('fetches one scope report with evidence sources through the native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'scope-report-1',
        name: 'Organization scope report',
        status: 'Done',
        scope: {id: 'scope-1', name: 'Organization'},
        protection_requirement: 'high',
        source_report_count: 1,
        member_host_count: 2,
        evidence_host_count: 2,
        missing_host_count: 0,
        result_count: 12,
        vulnerability_count: 3,
        severity: {high: 1, medium: 2, low: 0, log: 9, false_positive: 0},
        max_severity: 9.8,
        latest_evidence_time: '2026-06-21T10:00:00Z',
        excluded_candidate_host_count: 0,
        creation_time: '2026-06-21T10:00:00Z',
        sources: [
          {
            id: 'source-1',
            source_report_id: 'raw-report-1',
            target_id: 'target-1',
            target_name: 'Target 1',
            task_id: 'task-1',
            task_name: 'Task 1',
            scan_end: '2026-06-21T09:59:00Z',
            selected: true,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const report = await fetchNativeScopeReport(gmp, 'scope-report-1');

    expect(report.id).toEqual('scope-report-1');
    expect(report.scopeName).toEqual('Organization');
    expect(report.protectionRequirement).toEqual('high');
    expect(report.sources).toHaveLength(1);
    expect(report.sources[0].sourceReportId).toEqual('raw-report-1');
    expect(report.sources[0].targetName).toEqual('Target 1');
    expect(report.sources[0].taskName).toEqual('Task 1');
    expect(report.sources[0].selected).toEqual(true);
    expect(report.topResults).toEqual([]);
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/scope-reports/scope-report-1',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scope-reports/scope-report-1',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('fetches paginated scope reports through the same-origin native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 2, page_size: 25, total: 42, sort: '-creation_time', filter: 'org'},
        items: [
          {
            id: 'scope-report-1',
            name: 'Organization scope report',
            status: 'Done',
            scope: {id: 'scope-1', name: 'Organization'},
            protection_requirement: 'Very High',
            source_report_count: 4,
            member_host_count: 7,
            evidence_host_count: 6,
            missing_host_count: 1,
            result_count: 799,
            vulnerability_count: 581,
            severity: {high: 263, medium: 276, low: 42, log: 218, false_positive: 0},
            max_severity: 10.0,
            latest_evidence_time: '2026-06-15T16:16:29Z',
            excluded_candidate_host_count: 3,
            creation_time: '2026-06-15T16:16:29Z',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeScopeReports(gmp, {
      page: 2,
      pageSize: 25,
      sort: '-creation_time',
      filter: 'org',
    });

    expect(response.counts.filtered).toEqual(42);
    expect(response.reports[0].scopeName).toEqual('Organization');
    expect(response.reports[0].protectionRequirement).toEqual('very_high');
    expect(response.reports[0].hostsWithEvidence).toEqual(6);
    expect(response.reports[0].severityHigh).toEqual(263);
    expect(response.reports[0].resultsTotal).toEqual(799);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/scope-reports', {
      token: 'test-token',
      page: 2,
      page_size: 25,
      sort: '-creation_time',
      filter: 'org',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scope-reports',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });
});
