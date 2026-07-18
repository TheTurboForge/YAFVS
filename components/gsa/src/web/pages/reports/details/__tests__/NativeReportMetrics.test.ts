/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {
  fetchNativeReportMetrics,
  fetchNativeScopeReportMetrics,
  mapNativeMetrics,
} from 'gmp/native-api/report-metrics';

const nativePayload = {
  id: 'report-1',
  summary: {
    alive_system_count: 2,
    total_system_cvss_load: 12.5,
    average_system_cvss_load: 6.25,
    vulnerability_count: 3,
    authenticated_system_count: 1,
    authentication_failed_system_count: 0,
    no_credential_path_system_count: 1,
    unknown_authentication_system_count: 0,
    authenticated_scan_coverage_percent: 50,
  },
  systems: [
    {
      host: '192.0.2.10',
      cvss_load: 8.5,
      max_cvss: 8.5,
      vulnerability_count: 1,
      authentication_state: 'Authenticated',
      source_report_count: 1,
    },
    {
      host: '192.0.2.11',
      cvss_load: 4,
      max_cvss: 4,
      vulnerability_count: 2,
      authentication_state: 'No Credential Path',
      source_report_count: 2,
    },
  ],
  vulnerabilities: [
    {
      nvt_oid: '1.3.6.1.4.1.25623.1.0.1',
      name: 'Example vulnerability',
      cvss_score: 8.5,
      affected_system_count: 1,
      cvss_load: 8.5,
      average_contribution: 4.25,
      source_report_count: 1,
    },
  ],
};

const createGmp = ({
  jwt,
  token = 'test-token',
}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string, params?: Record<string, string>) => {
    const suffix = params?.token ? `?token=${params.token}` : '';
    return `https://yafvs.example/${path}${suffix}`;
  }),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API report metrics', () => {
  test('maps sidecar JSON to the existing report metrics model', () => {
    const metrics = mapNativeMetrics(nativePayload);

    expect(metrics.id).toEqual('report-1');
    expect(metrics.summary.averageSystemCvssLoad).toEqual(6.25);
    expect(metrics.summary.authenticatedScanCoveragePercent).toEqual(50);
    expect(metrics.systems[0].authenticationState).toEqual('authenticated');
    expect(metrics.systems[1].authenticationState).toEqual(
      'no_credential_path',
    );
    expect(metrics.vulnerabilities[0].nvtOid).toEqual(
      '1.3.6.1.4.1.25623.1.0.1',
    );
  });

  test('fetches raw report metrics through same-origin native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue(nativePayload),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const metrics = await fetchNativeReportMetrics(gmp, 'report/id');

    expect(metrics.id).toEqual('report-1');
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/reports/report%2Fid/metrics',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/reports/report%2Fid/metrics?token=test-token',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('fetches scope report metrics through same-origin native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue(nativePayload),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();

    await fetchNativeScopeReportMetrics(gmp, 'scope-1', 'scope-report-1');

    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/scopes/scope-1/reports/scope-report-1/metrics',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/scopes/scope-1/reports/scope-report-1/metrics?token=test-token',
      {
        credentials: 'include',
        headers: {Accept: 'application/json'},
      },
    );
  });

  test('raises a clear error for failed native API responses', async () => {
    testing.stubGlobal(
      'fetch',
      testing.fn().mockResolvedValue({ok: false, status: 502}),
    );
    const gmp = createGmp();

    await expect(fetchNativeReportMetrics(gmp, 'report-1')).rejects.toThrow(
      'Native API request failed with status 502',
    );
  });
});
