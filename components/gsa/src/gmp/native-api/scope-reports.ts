/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import type {ProtectionRequirement, ScopeReport} from 'gmp/commands/scopes';
import type {UrlParams} from 'gmp/http/utils';
import Filter from 'gmp/models/filter';

interface NativeApiSession {
  readonly jwt?: string;
  readonly token?: string;
}

interface NativeApiGmp {
  readonly session: NativeApiSession;
  buildUrl(path: string, params?: UrlParams): string;
}

interface NativeScopeReportScope {
  id?: string;
  name?: string;
}

interface NativeScopeReportSeverityCounts {
  high?: number;
  medium?: number;
  low?: number;
  log?: number;
  false_positive?: number;
}

interface NativeScopeReportMetricsSummary {
  total_system_cvss_load?: number;
  average_system_cvss_load?: number;
  authenticated_scan_coverage_percent?: number;
  alive_system_count?: number;
  vulnerability_count?: number;
  authenticated_system_count?: number;
  authentication_failed_system_count?: number;
  no_credential_path_system_count?: number;
  unknown_authentication_system_count?: number;
}

interface NativeScopeReportSourceItem {
  id?: string;
  source_report_id?: string;
  source_report_name?: string;
  target_id?: string;
  target_name?: string;
  task_id?: string;
  task_name?: string;
  scan_end?: string;
  selected?: boolean;
  reason?: string;
}

interface NativeScopeReportItem {
  id?: string;
  name?: string;
  status?: string;
  scope?: NativeScopeReportScope;
  protection_requirement?: string;
  source_report_count?: number;
  source_target_count?: number;
  member_host_count?: number;
  evidence_host_count?: number;
  missing_host_count?: number;
  result_count?: number;
  vulnerability_count?: number;
  severity?: NativeScopeReportSeverityCounts;
  max_severity?: number;
  latest_evidence_time?: string;
  excluded_candidate_host_count?: number;
  creation_time?: string;
  modification_time?: string;
  metrics_summary?: NativeScopeReportMetricsSummary;
  sources?: NativeScopeReportSourceItem[];
}

interface NativeScopeReportPage {
  page: number;
  page_size: number;
  total: number;
  sort: string;
  filter: string;
}

interface NativeScopeReportCollectionPayload {
  page?: Partial<NativeScopeReportPage>;
  items?: NativeScopeReportItem[];
}

export interface NativeScopeReportQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
}

export interface NativeScopeReportsResponse {
  reports: ScopeReport[];
  counts: CollectionCounts;
  page: NativeScopeReportPage;
}

const SCOPE_REPORT_SORT_FIELDS: Record<string, string> = {
  created: 'creation_time',
  creation_time: 'creation_time',
  modified: 'modification_time',
  modification_time: 'modification_time',
  latest_evidence: 'latest_evidence_time',
  latest_evidence_time: 'latest_evidence_time',
  scope: 'scope_name',
  scope_name: 'scope_name',
  severity: 'max_severity',
  max_severity: 'max_severity',
  source_reports: 'source_report_count',
  source_report_count: 'source_report_count',
  hosts: 'member_host_count',
  member_host_count: 'member_host_count',
  results: 'result_count',
  result_count: 'result_count',
  vulnerabilities: 'vulnerability_count',
  vulnerability_count: 'vulnerability_count',
};

const integerValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const numberValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseFloat(String(value ?? fallback));
  return Number.isFinite(parsed) ? parsed : fallback;
};

const stringValue = (value: unknown, fallback = ''): string =>
  typeof value === 'string' ? value : fallback;

const optionalStringValue = (value: unknown): string | undefined =>
  typeof value === 'string' && value.length > 0 ? value : undefined;

const nativeSortFromFilter = (filter?: Filter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  if (reverse === undefined && ascending === undefined) {
    return '-creation_time';
  }
  const rawField = stringValue(reverse ?? ascending, 'creation_time');
  const nativeField = SCOPE_REPORT_SORT_FIELDS[rawField] ?? rawField;
  return reverse !== undefined ? `-${nativeField}` : nativeField;
};

const nativeSearchFromFilter = (filter?: Filter): string => {
  const search = filter?.get('search');
  if (search !== undefined) {
    return String(search);
  }
  const criteria = filter?.toFilterCriteriaString().trim() ?? '';
  return /[=<>:~]/.test(criteria) ? '' : criteria;
};

export const nativeScopeReportQueryFromFilter = (
  filter?: Filter,
  scopeId?: string,
): NativeScopeReportQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  const search = nativeSearchFromFilter(filter);
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeSortFromFilter(filter),
    filter: search || scopeId || '',
  };
};

export const canUseNativeScopeReportList = (
  filter?: Filter,
  scopeId?: string,
): boolean => {
  if (scopeId === undefined) {
    return true;
  }
  return nativeSearchFromFilter(filter) === '';
};

const nativeCounts = (page: NativeScopeReportPage, length: number) =>
  new CollectionCounts({
    first: page.total > 0 ? (page.page - 1) * page.page_size + 1 : 0,
    all: page.total,
    filtered: page.total,
    length,
    rows: page.page_size,
  });

const protectionValue = (value: unknown): ProtectionRequirement => {
  switch (stringValue(value).toLowerCase().replace(/\s+/g, '_')) {
    case 'high':
      return 'high';
    case 'very_high':
      return 'very_high';
    default:
      return 'normal';
  }
};

const nativeMetricsSummaryToModel = (
  summary: NativeScopeReportMetricsSummary | undefined,
) => {
  if (summary === undefined) {
    return undefined;
  }
  return {
    totalSystemCvssLoad: numberValue(summary.total_system_cvss_load),
    averageSystemCvssLoad: numberValue(summary.average_system_cvss_load),
    authenticatedScanCoveragePercent: numberValue(
      summary.authenticated_scan_coverage_percent,
    ),
    aliveSystemCount: integerValue(summary.alive_system_count),
    vulnerabilityCount: integerValue(summary.vulnerability_count),
    authenticatedSystemCount: integerValue(summary.authenticated_system_count),
    authenticationFailedSystemCount: integerValue(
      summary.authentication_failed_system_count,
    ),
    noCredentialPathSystemCount: integerValue(
      summary.no_credential_path_system_count,
    ),
    unknownAuthenticationSystemCount: integerValue(
      summary.unknown_authentication_system_count,
    ),
  };
};

const booleanValue = (value: unknown, fallback = false): boolean => {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    return value !== 0;
  }
  if (typeof value === 'string') {
    return ['1', 'true', 'yes'].includes(value.toLowerCase());
  }
  return fallback;
};

const nativeScopeReportSourceToModel = (
  source: NativeScopeReportSourceItem,
) => ({
  id: optionalStringValue(source.id),
  sourceReportId: optionalStringValue(source.source_report_id),
  sourceReportName: optionalStringValue(source.source_report_name),
  targetId: optionalStringValue(source.target_id),
  targetName: optionalStringValue(source.target_name),
  taskId: optionalStringValue(source.task_id),
  taskName: optionalStringValue(source.task_name),
  scanEnd: optionalStringValue(source.scan_end),
  selected: booleanValue(source.selected, true),
  reason: optionalStringValue(source.reason),
});

const protectionLabel = (value: unknown): string => {
  switch (protectionValue(value)) {
    case 'high':
      return 'High';
    case 'very_high':
      return 'Very High';
    default:
      return 'Normal';
  }
};

export const nativeScopeReportToModel = (
  item: NativeScopeReportItem,
): ScopeReport => {
  const scope = item.scope ?? {};
  const severity = item.severity ?? {};
  return {
    id: stringValue(item.id),
    name: stringValue(item.name, stringValue(item.id)),
    created: optionalStringValue(item.creation_time),
    latestEvidenceTime: optionalStringValue(item.latest_evidence_time),
    sourceReportCount: integerValue(item.source_report_count),
    hostsTotal: integerValue(item.member_host_count),
    hostsWithEvidence: integerValue(item.evidence_host_count),
    hostsMissingEvidence: integerValue(item.missing_host_count),
    resultsTotal: integerValue(item.result_count),
    vulnerabilitiesTotal: integerValue(item.vulnerability_count),
    severityHigh: integerValue(severity.high),
    severityMedium: integerValue(severity.medium),
    severityLow: integerValue(severity.low),
    severityLog: integerValue(severity.log),
    severityFalsePositive: integerValue(severity.false_positive),
    maxSeverity: numberValue(item.max_severity),
    excludedCandidateHosts: integerValue(item.excluded_candidate_host_count),
    metricsSummary: nativeMetricsSummaryToModel(item.metrics_summary),
    scopeId: stringValue(scope.id),
    scopeName: stringValue(scope.name),
    protectionRequirement: protectionValue(item.protection_requirement),
    protectionRequirementLabel: protectionLabel(item.protection_requirement),
    sources: (item.sources ?? []).map(nativeScopeReportSourceToModel),
    topResults: [],
  };
};

export const fetchNativeScopeReport = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<ScopeReport> => {
  const headers: HeadersInit = {Accept: 'application/json'};
  if (gmp.session.jwt) {
    headers.Authorization = `Bearer ${gmp.session.jwt}`;
  }

  const response = await fetch(
    gmp.buildUrl(`api/v1/scope-reports/${encodeURIComponent(id)}`, {
      token: gmp.session.token,
    }),
    {
      credentials: 'include',
      headers,
    },
  );
  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }

  return nativeScopeReportToModel(
    (await response.json()) as NativeScopeReportItem,
  );
};

export const fetchNativeScopeReports = async (
  gmp: NativeApiGmp,
  query: NativeScopeReportQuery,
): Promise<NativeScopeReportsResponse> => {
  const headers: HeadersInit = {Accept: 'application/json'};
  if (gmp.session.jwt) {
    headers.Authorization = `Bearer ${gmp.session.jwt}`;
  }

  const response = await fetch(
    gmp.buildUrl('api/v1/scope-reports', {
      token: gmp.session.token,
      page: query.page,
      page_size: query.pageSize,
      sort: query.sort,
      filter: query.filter,
    }),
    {
      credentials: 'include',
      headers,
    },
  );
  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }

  const payload = (await response.json()) as NativeScopeReportCollectionPayload;
  const page = {
    page: integerValue(payload.page?.page, 1),
    page_size: integerValue(payload.page?.page_size, query.pageSize),
    total: integerValue(payload.page?.total),
    sort: stringValue(payload.page?.sort),
    filter: stringValue(payload.page?.filter),
  };
  const reports = (payload.items ?? []).map(nativeScopeReportToModel);
  return {
    reports,
    counts: nativeCounts(page, reports.length),
    page,
  };
};

export const deleteNativeScopeReport = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<void> => {
  const response = await fetch(
    gmp.buildUrl(`api/v1/scope-reports/${encodeURIComponent(id)}`),
    {
      method: 'DELETE',
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        ...(gmp.session.token === undefined
          ? {}
          : {'X-TurboVAS-Token': gmp.session.token}),
        ...(gmp.session.jwt === undefined
          ? {}
          : {Authorization: `Bearer ${gmp.session.jwt}`}),
      },
    },
  );
  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }
};
