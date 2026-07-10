/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type {UrlParams} from 'gmp/http/utils';

export interface ReportMetricsSummary {
  aliveSystemCount: number;
  totalSystemCvssLoad: number;
  averageSystemCvssLoad: number;
  vulnerabilityCount: number;
  authenticatedSystemCount: number;
  authenticationFailedSystemCount: number;
  noCredentialPathSystemCount: number;
  unknownAuthenticationSystemCount: number;
  authenticatedScanCoveragePercent: number;
}

export interface ReportMetricSystem {
  host: string;
  cvssLoad: number;
  maxCvss: number;
  vulnerabilityCount: number;
  authenticationState: string;
  sourceReportCount: number;
}

export interface ReportMetricVulnerability {
  nvtOid: string;
  name: string;
  cvssScore: number;
  affectedSystemCount: number;
  cvssLoad: number;
  averageContribution: number;
  sourceReportCount: number;
}

export interface ReportMetrics {
  id: string;
  summary: ReportMetricsSummary;
  systems: ReportMetricSystem[];
  vulnerabilities: ReportMetricVulnerability[];
}

interface NativeApiSession {
  readonly jwt?: string;
  readonly token?: string;
}

interface NativeApiGmp {
  readonly session: NativeApiSession;
  buildUrl(path: string, params?: UrlParams): string;
}

type NativeMetrics = Record<string, unknown>;

const asRecord = (value: unknown): Record<string, unknown> => {
  if (typeof value === 'object' && value !== null) {
    return value as Record<string, unknown>;
  }
  return {};
};

const asArray = (value: unknown): Record<string, unknown>[] => {
  return Array.isArray(value) ? value.map(asRecord) : [];
};

const stringValue = (value: unknown, fallback = ''): string => {
  return typeof value === 'string' ? value : fallback;
};

const numberValue = (value: unknown): number => {
  const parsed =
    typeof value === 'number' ? value : Number.parseFloat(String(value ?? 0));
  return Number.isFinite(parsed) ? parsed : 0;
};

const integerValue = (value: unknown): number => {
  const parsed =
    typeof value === 'number' ? value : Number.parseInt(String(value ?? 0), 10);
  return Number.isFinite(parsed) ? parsed : 0;
};

const authenticationState = (value: unknown): string => {
  return stringValue(value, 'Unknown').toLowerCase().replaceAll(' ', '_');
};

export const mapNativeMetrics = (payload: NativeMetrics): ReportMetrics => {
  const summary = asRecord(payload.summary);
  return {
    id: stringValue(payload.id),
    summary: {
      aliveSystemCount: integerValue(summary.alive_system_count),
      totalSystemCvssLoad: numberValue(summary.total_system_cvss_load),
      averageSystemCvssLoad: numberValue(summary.average_system_cvss_load),
      vulnerabilityCount: integerValue(summary.vulnerability_count),
      authenticatedSystemCount: integerValue(
        summary.authenticated_system_count,
      ),
      authenticationFailedSystemCount: integerValue(
        summary.authentication_failed_system_count,
      ),
      noCredentialPathSystemCount: integerValue(
        summary.no_credential_path_system_count,
      ),
      unknownAuthenticationSystemCount: integerValue(
        summary.unknown_authentication_system_count,
      ),
      authenticatedScanCoveragePercent: numberValue(
        summary.authenticated_scan_coverage_percent,
      ),
    },
    systems: asArray(payload.systems).map(system => ({
      host: stringValue(system.host),
      cvssLoad: numberValue(system.cvss_load),
      maxCvss: numberValue(system.max_cvss),
      vulnerabilityCount: integerValue(system.vulnerability_count),
      authenticationState: authenticationState(system.authentication_state),
      sourceReportCount: integerValue(system.source_report_count),
    })),
    vulnerabilities: asArray(payload.vulnerabilities).map(vulnerability => ({
      nvtOid: stringValue(vulnerability.nvt_oid),
      name: stringValue(vulnerability.name),
      cvssScore: numberValue(vulnerability.cvss_score),
      affectedSystemCount: integerValue(vulnerability.affected_system_count),
      cvssLoad: numberValue(vulnerability.cvss_load),
      averageContribution: numberValue(vulnerability.average_contribution),
      sourceReportCount: integerValue(vulnerability.source_report_count),
    })),
  };
};

const fetchNativeMetrics = async (
  gmp: NativeApiGmp,
  path: string,
): Promise<ReportMetrics> => {
  const headers: HeadersInit = {Accept: 'application/json'};
  if (gmp.session.jwt) {
    headers.Authorization = `Bearer ${gmp.session.jwt}`;
  }

  const response = await fetch(gmp.buildUrl(path, {token: gmp.session.token}), {
    credentials: 'include',
    headers,
  });
  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }

  return mapNativeMetrics(await response.json());
};

export const fetchNativeReportMetrics = (
  gmp: NativeApiGmp,
  reportId: string,
) => {
  return fetchNativeMetrics(
    gmp,
    `api/v1/reports/${encodeURIComponent(reportId)}/metrics`,
  );
};

export const fetchNativeScopeReportMetrics = (
  gmp: NativeApiGmp,
  scopeId: string,
  scopeReportId: string,
) => {
  return fetchNativeMetrics(
    gmp,
    `api/v1/scopes/${encodeURIComponent(scopeId)}/reports/${encodeURIComponent(
      scopeReportId,
    )}/metrics`,
  );
};
