/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import type Filter from 'gmp/models/filter';
import Report from 'gmp/models/report';
import type {UrlParams} from 'gmp/http/utils';

interface NativeApiSession {
  readonly jwt?: string;
  readonly token?: string;
}

interface NativeApiGmp {
  readonly session: NativeApiSession;
  buildUrl(path: string, params?: UrlParams): string;
}

interface NativeReportReference {
  id: string;
  name: string;
}

interface NativeReportSeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  log: number;
  false_positive: number;
}

interface NativeReportItem {
  id: string;
  name: string;
  status: string;
  task?: NativeReportReference;
  target?: NativeReportReference;
  scan_start?: string;
  scan_end?: string;
  creation_time?: string;
  modification_time?: string;
  result_count: number;
  vulnerability_count: number;
  host_count: number;
  cve_count: number;
  severity: NativeReportSeverityCounts;
  max_severity: number;
}

interface NativeReportPage {
  page: number;
  page_size: number;
  total: number;
  sort: string;
  filter: string;
}

interface NativeReportCollectionPayload {
  page?: Partial<NativeReportPage>;
  items?: NativeReportItem[];
}

interface NativeReportResultPayload {
  id: string;
  host: string;
  hostname?: string;
  port: string;
  nvt_oid: string;
  name: string;
  nvt_family?: string;
  description_excerpt?: string;
  severity: number;
  qod: number;
  created_at?: string;
  source_report_id: string;
  raw_evidence_href: string;
}

interface NativeReportResultsPayload {
  page?: Partial<NativeReportPage>;
  items?: NativeReportResultPayload[];
}

interface NativeReportHostPayload {
  host: string;
  hostname?: string;
  best_os_cpe?: string;
  best_os_txt?: string;
  ports_count: number;
  applications_count: number;
  distance?: number;
  authentication_state: string;
  start_time?: string;
  end_time?: string;
  result_count: number;
  vulnerability_count: number;
  severity: NativeReportSeverityCounts;
  max_severity: number;
  source_report_id: string;
}

interface NativeReportHostsPayload {
  page?: Partial<NativeReportPage>;
  items?: NativeReportHostPayload[];
}

interface NativeReportPortPayload {
  port: string;
  protocol: string;
  host_count: number;
  result_count: number;
  vulnerability_count: number;
  max_severity: number;
  source_report_ids?: string[];
}

interface NativeReportPortsPayload {
  page?: Partial<NativeReportPage>;
  items?: NativeReportPortPayload[];
}

type NativeReportDetailPayload = NativeReportItem;

export interface NativeReportQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
}

export interface NativeReportsResponse {
  reports: Report[];
  counts: CollectionCounts;
  page: NativeReportPage;
}

export interface NativeReportResponse {
  report: Report;
}

export interface NativeReportResultItem {
  id: string;
  host: string;
  hostname?: string;
  port: string;
  nvtOid: string;
  name: string;
  nvtFamily?: string;
  descriptionExcerpt?: string;
  severity: number;
  qod: number;
  createdAt?: string;
  sourceReportId: string;
  rawEvidenceHref: string;
}

export interface NativeReportResultsResponse {
  items: NativeReportResultItem[];
  page: NativeReportPage;
}

export interface NativeReportHostItem {
  host: string;
  hostname?: string;
  bestOsCpe?: string;
  bestOsTxt?: string;
  portsCount: number;
  applicationsCount: number;
  distance?: number;
  authenticationState: string;
  startTime?: string;
  endTime?: string;
  resultCount: number;
  vulnerabilityCount: number;
  severity: NativeReportSeverityCounts;
  maxSeverity: number;
  sourceReportId: string;
}

export interface NativeReportHostsResponse {
  items: NativeReportHostItem[];
  page: NativeReportPage;
}

export interface NativeReportPortItem {
  port: string;
  protocol: string;
  hostCount: number;
  resultCount: number;
  vulnerabilityCount: number;
  maxSeverity: number;
  sourceReportIds: string[];
}

export interface NativeReportPortsResponse {
  items: NativeReportPortItem[];
  page: NativeReportPage;
}

const REPORT_SORT_FIELDS: Record<string, string> = {
  date: 'creation_time',
  creation_time: 'creation_time',
  status: 'status',
  task: 'task',
  target: 'target',
  severity: 'severity',
  result_count: 'result_count',
  vulnerability_count: 'vulnerability_count',
  host_count: 'host_count',
  cve_count: 'cve_count',
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  log: 'log',
  false_positive: 'false_positive',
};

const RESULT_SORT_FIELDS: Record<string, string> = {
  created: 'created_at',
  created_at: 'created_at',
  host: 'host',
  name: 'name',
  nvt: 'nvt_oid',
  nvt_oid: 'nvt_oid',
  port: 'port',
  qod: 'qod',
  severity: 'severity',
};

const HOST_SORT_FIELDS: Record<string, string> = {
  appsCount: 'applications_count',
  applications_count: 'applications_count',
  critical: 'critical',
  distance: 'distance',
  end: 'end_time',
  end_time: 'end_time',
  false_positive: 'false_positive',
  high: 'high',
  hostname: 'hostname',
  ip: 'host',
  log: 'log',
  low: 'low',
  medium: 'medium',
  portsCount: 'ports_count',
  ports_count: 'ports_count',
  result_count: 'result_count',
  severity: 'severity',
  start: 'start_time',
  start_time: 'start_time',
  total: 'result_count',
  vulnerability_count: 'vulnerability_count',
};

const PORT_SORT_FIELDS: Record<string, string> = {
  host_count: 'host_count',
  hosts: 'host_count',
  max_severity: 'max_severity',
  name: 'port',
  port: 'port',
  protocol: 'protocol',
  result_count: 'result_count',
  severity: 'max_severity',
  vulnerability_count: 'vulnerability_count',
};

const integerValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const nativePortSortFromFilter = (filter?: Filter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending) || 'port';
  const nativeField = PORT_SORT_FIELDS[rawField] ?? rawField;
  return reverse !== undefined ? `-${nativeField}` : nativeField;
};

const numberValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseFloat(String(value ?? fallback));
  return Number.isFinite(parsed) ? parsed : fallback;
};

export const nativeReportPortsQueryFromFilter = (
  filter?: Filter,
): NativeReportQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativePortSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
  };
};

const stringValue = (value: unknown): string =>
  typeof value === 'string' ? value : '';

const nativeSortFromFilter = (filter?: Filter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending) || 'creation_time';
  const nativeField = REPORT_SORT_FIELDS[rawField] ?? rawField;
  return reverse !== undefined ? `-${nativeField}` : nativeField;
};

const nativeHostSortFromFilter = (filter?: Filter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending) || 'host';
  const nativeField = HOST_SORT_FIELDS[rawField] ?? rawField;
  return reverse !== undefined ? `-${nativeField}` : nativeField;
};

const nativeResultSortFromFilter = (filter?: Filter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending) || 'severity';
  const nativeField = RESULT_SORT_FIELDS[rawField] ?? rawField;
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

export const nativeReportResultsQueryFromFilter = (
  filter?: Filter,
): NativeReportQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeResultSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
  };
};

export const nativeReportHostsQueryFromFilter = (
  filter?: Filter,
): NativeReportQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeHostSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
  };
};

export const nativeReportQueryFromFilter = (filter?: Filter): NativeReportQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
  };
};

const nativeReportResultFromPayload = (
  item: NativeReportResultPayload,
): NativeReportResultItem => ({
  id: stringValue(item.id),
  host: stringValue(item.host),
  hostname: stringValue(item.hostname) || undefined,
  port: stringValue(item.port),
  nvtOid: stringValue(item.nvt_oid),
  name: stringValue(item.name),
  nvtFamily: stringValue(item.nvt_family) || undefined,
  descriptionExcerpt: stringValue(item.description_excerpt) || undefined,
  severity: numberValue(item.severity),
  qod: integerValue(item.qod),
  createdAt: stringValue(item.created_at) || undefined,
  sourceReportId: stringValue(item.source_report_id),
  rawEvidenceHref: stringValue(item.raw_evidence_href),
});

const nativeReportHostFromPayload = (
  item: NativeReportHostPayload,
): NativeReportHostItem => ({
  host: stringValue(item.host),
  hostname: stringValue(item.hostname) || undefined,
  bestOsCpe: stringValue(item.best_os_cpe) || undefined,
  bestOsTxt: stringValue(item.best_os_txt) || undefined,
  portsCount: integerValue(item.ports_count),
  applicationsCount: integerValue(item.applications_count),
  distance:
    item.distance === undefined || item.distance === null
      ? undefined
      : integerValue(item.distance),
  authenticationState: stringValue(item.authentication_state),
  startTime: stringValue(item.start_time) || undefined,
  endTime: stringValue(item.end_time) || undefined,
  resultCount: integerValue(item.result_count),
  vulnerabilityCount: integerValue(item.vulnerability_count),
  severity: {
    critical: integerValue(item.severity?.critical),
    high: integerValue(item.severity?.high),
    medium: integerValue(item.severity?.medium),
    low: integerValue(item.severity?.low),
    log: integerValue(item.severity?.log),
    false_positive: integerValue(item.severity?.false_positive),
  },
  maxSeverity: numberValue(item.max_severity),
  sourceReportId: stringValue(item.source_report_id),
});

const nativeReportPortFromPayload = (
  item: NativeReportPortPayload,
): NativeReportPortItem => ({
  port: stringValue(item.port),
  protocol: stringValue(item.protocol),
  hostCount: integerValue(item.host_count),
  resultCount: integerValue(item.result_count),
  vulnerabilityCount: integerValue(item.vulnerability_count),
  maxSeverity: numberValue(item.max_severity),
  sourceReportIds: Array.isArray(item.source_report_ids)
    ? item.source_report_ids.filter(value => typeof value === 'string')
    : [],
});

const nativeCounts = (page: NativeReportPage, length: number) =>
  new CollectionCounts({
    first: page.total > 0 ? (page.page - 1) * page.page_size + 1 : 0,
    all: page.total,
    filtered: page.total,
    length,
    rows: page.page_size,
  });

const resultCountElement = (count: number) => ({filtered: count, full: count});

export const nativeReportToModel = (item: NativeReportItem): Report => {
  const task = item.task
    ? {
        _id: item.task.id,
        name: item.task.name,
        progress: item.status === 'Done' ? 100 : undefined,
        target: item.target
          ? {
              _id: item.target.id,
              name: item.target.name,
            }
          : undefined,
      }
    : undefined;

  const timestamp = item.creation_time ?? item.scan_end ?? item.scan_start;
  const severity = resultCountElement(item.max_severity);
  return Report.fromElement({
    _id: item.id,
    name: item.name,
    creation_time: item.creation_time,
    modification_time: item.modification_time,
    task: item.task
      ? {
          _id: item.task.id,
          name: item.task.name,
        }
      : undefined,
    report: {
      _id: item.id,
      _type: 'scan',
      timestamp,
      scan_start: item.scan_start,
      scan_end: item.scan_end,
      scan_run_status: item.status,
      severity,
      task,
      hosts: {count: item.host_count},
      vulns: {count: item.vulnerability_count},
      result_count: {
        filtered: item.result_count,
        full: item.result_count,
        critical: resultCountElement(item.severity.critical),
        high: resultCountElement(item.severity.high),
        medium: resultCountElement(item.severity.medium),
        low: resultCountElement(item.severity.low),
        log: resultCountElement(item.severity.log),
        false_positive: resultCountElement(item.severity.false_positive),
      },
      timezone: 'UTC',
      timezone_abbrev: 'UTC',
    },
  });
};

const nativeHeaders = (gmp: NativeApiGmp): HeadersInit => {
  const headers: HeadersInit = {Accept: 'application/json'};
  if (gmp.session.jwt) {
    headers.Authorization = `Bearer ${gmp.session.jwt}`;
  }
  return headers;
};

const fetchNativeJson = async <T>(
  gmp: NativeApiGmp,
  path: string,
  params: UrlParams,
): Promise<T> => {
  const response = await fetch(gmp.buildUrl(path, params), {
    credentials: 'include',
    headers: nativeHeaders(gmp),
  });
  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }
  return (await response.json()) as T;
};

export const fetchNativeReport = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<NativeReportResponse> => {
  const payload = await fetchNativeJson<NativeReportDetailPayload>(
    gmp,
    `api/v1/reports/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return {report: nativeReportToModel(payload)};
};

export const fetchNativeReports = async (
  gmp: NativeApiGmp,
  query: NativeReportQuery,
): Promise<NativeReportsResponse> => {
  const payload = await fetchNativeJson<NativeReportCollectionPayload>(
    gmp,
    'api/v1/reports',
    {
      token: gmp.session.token,
      page: query.page,
      page_size: query.pageSize,
      sort: query.sort,
      filter: query.filter,
    },
  );
  const page = {
    page: integerValue(payload.page?.page, 1),
    page_size: integerValue(payload.page?.page_size, query.pageSize),
    total: integerValue(payload.page?.total),
    sort: stringValue(payload.page?.sort),
    filter: stringValue(payload.page?.filter),
  };
  const reports = (payload.items ?? []).map(nativeReportToModel);
  return {
    reports,
    counts: nativeCounts(page, reports.length),
    page,
  };
};

export const fetchNativeReportResults = async (
  gmp: NativeApiGmp,
  reportId: string,
  query: NativeReportQuery,
): Promise<NativeReportResultsResponse> => {
  const payload = await fetchNativeJson<NativeReportResultsPayload>(
    gmp,
    `api/v1/reports/${encodeURIComponent(reportId)}/results`,
    {
      token: gmp.session.token,
      page: query.page,
      page_size: query.pageSize,
      sort: query.sort,
      filter: query.filter,
    },
  );
  const page = {
    page: integerValue(payload.page?.page, 1),
    page_size: integerValue(payload.page?.page_size, query.pageSize),
    total: integerValue(payload.page?.total),
    sort: stringValue(payload.page?.sort),
    filter: stringValue(payload.page?.filter),
  };
  return {
    items: (payload.items ?? []).map(nativeReportResultFromPayload),
    page,
  };
};

export const fetchNativeReportHosts = async (
  gmp: NativeApiGmp,
  reportId: string,
  query: NativeReportQuery,
): Promise<NativeReportHostsResponse> => {
  const payload = await fetchNativeJson<NativeReportHostsPayload>(
    gmp,
    `api/v1/reports/${encodeURIComponent(reportId)}/hosts`,
    {
      token: gmp.session.token,
      page: query.page,
      page_size: query.pageSize,
      sort: query.sort,
      filter: query.filter,
    },
  );
  const page = {
    page: integerValue(payload.page?.page, 1),
    page_size: integerValue(payload.page?.page_size, query.pageSize),
    total: integerValue(payload.page?.total),
    sort: stringValue(payload.page?.sort),
    filter: stringValue(payload.page?.filter),
  };
  return {
    items: (payload.items ?? []).map(nativeReportHostFromPayload),
    page,
  };
};

export const fetchNativeReportPorts = async (
  gmp: NativeApiGmp,
  reportId: string,
  query: NativeReportQuery,
): Promise<NativeReportPortsResponse> => {
  const payload = await fetchNativeJson<NativeReportPortsPayload>(
    gmp,
    `api/v1/reports/${encodeURIComponent(reportId)}/ports`,
    {
      token: gmp.session.token,
      page: query.page,
      page_size: query.pageSize,
      sort: query.sort,
      filter: query.filter,
    },
  );
  const page = {
    page: integerValue(payload.page?.page, 1),
    page_size: integerValue(payload.page?.page_size, query.pageSize),
    total: integerValue(payload.page?.total),
    sort: stringValue(payload.page?.sort),
    filter: stringValue(payload.page?.filter),
  };
  return {
    items: (payload.items ?? []).map(nativeReportPortFromPayload),
    page,
  };
};
