/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import type {UrlParams} from 'gmp/http/utils';
import type Filter from 'gmp/models/filter';
import Report from 'gmp/models/report';
import Result from 'gmp/models/result';

interface NativeApiSession {
  readonly jwt?: string;
  readonly token?: string;
}

interface NativeReportApplicationPayload {
  name: string;
  version?: string;
  cpe?: string;
  host_count: number;
  result_count: number;
  vulnerability_count: number;
  max_severity: number;
  source_report_ids?: string[];
}

interface NativeReportApplicationsPayload {
  page?: Partial<NativeReportPage>;
  items?: NativeReportApplicationPayload[];
}

interface NativeReportOperatingSystemPayload {
  name: string;
  cpe?: string;
  host_count: number;
  result_count: number;
  vulnerability_count: number;
  max_severity: number;
  source_report_ids?: string[];
}

interface NativeReportOperatingSystemsPayload {
  page?: Partial<NativeReportPage>;
  items?: NativeReportOperatingSystemPayload[];
}

interface NativeReportTlsCertificatePayload {
  id: string;
  fingerprint_sha256?: string;
  subject?: string;
  issuer?: string;
  serial?: string;
  not_before?: string;
  not_after?: string;
  host_count: number;
  port_count: number;
  result_count: number;
  source_report_ids?: string[];
}

interface NativeReportTlsCertificatesPayload {
  page?: Partial<NativeReportPage>;
  items?: NativeReportTlsCertificatePayload[];
}

interface NativeApiGmp {
  readonly session: NativeApiSession;
  buildUrl(path: string, params?: UrlParams): string;
}

interface NativeReportReference {
  id: string;
  name: string;
}

interface NativeReportOwner {
  name?: string;
}

interface NativeReportUserTag {
  id: string;
  name: string;
  value?: string | number;
  comment?: string;
}

interface NativeResultOverrideNvtPayload {
  id?: string;
  name?: string;
  type?: string;
}

interface NativeResultOverridePayload {
  id: string;
  nvt?: NativeResultOverrideNvtPayload;
  text?: string;
  text_excerpt?: boolean;
  hosts?: string;
  port?: string;
  severity?: number;
  new_severity?: number;
  active?: boolean;
  end_time?: string;
  created_at?: string;
  modified_at?: string;
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
  owner?: NativeReportOwner;
  status: string;
  progress?: number;
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
  user_tags?: NativeReportUserTag[];
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

interface NativeNvtEpssPayload {
  score?: number;
  percentile?: number;
  cve?: string;
  severity?: number;
}

interface NativeReportResultPayload {
  id: string;
  host: string;
  host_asset_id?: string;
  hostname?: string;
  port: string;
  nvt_oid: string;
  name: string;
  nvt_family?: string;
  cves?: string[];
  cert_refs?: string[];
  xrefs?: string[];
  max_epss?: NativeNvtEpssPayload;
  max_severity?: NativeNvtEpssPayload;
  description_excerpt?: string;
  description?: string;
  summary?: string;
  insight?: string;
  affected?: string;
  impact?: string;
  detection?: string;
  solution_type?: string;
  solution?: string;
  severity: number;
  qod: number;
  scan_nvt_version?: string;
  created_at?: string;
  report?: NativeReportReference;
  task?: NativeReportReference;
  source_report_id: string;
  raw_evidence_href: string;
  user_tags?: NativeReportUserTag[];
  overrides?: NativeResultOverridePayload[];
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

interface NativeReportCvePayload {
  id: string;
  affected_system_count: number;
  result_count: number;
  max_severity: number;
  source_report_ids?: string[];
}

interface NativeReportCvesPayload {
  page?: Partial<NativeReportPage>;
  items?: NativeReportCvePayload[];
}

interface NativeReportErrorPayload {
  id: string;
  host: string;
  port: string;
  nvt_oid: string;
  description: string;
  source_report_id: string;
  created_at?: string;
}

interface NativeReportErrorsPayload {
  page?: Partial<NativeReportPage>;
  items?: NativeReportErrorPayload[];
}

type NativeReportDetailPayload = NativeReportItem;

export interface NativeReportQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
  taskId?: string;
  nvtOid?: string;
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
  cves: string[];
  certRefs: string[];
  xrefs: string[];
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

export interface NativeResultsResponse {
  results: Result[];
  counts: CollectionCounts;
  page: NativeReportPage;
}

export interface NativeResultResponse {
  result: Result;
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

export interface NativeReportCveItem {
  id: string;
  affectedSystemCount: number;
  resultCount: number;
  maxSeverity: number;
  sourceReportIds: string[];
}

export interface NativeReportCvesResponse {
  items: NativeReportCveItem[];
  page: NativeReportPage;
}

export interface NativeReportApplicationItem {
  name: string;
  version: string;
  cpe: string;
  hostCount: number;
  resultCount: number;
  vulnerabilityCount: number;
  maxSeverity: number;
  sourceReportIds: string[];
}

export interface NativeReportApplicationsResponse {
  items: NativeReportApplicationItem[];
  page: NativeReportPage;
}

export interface NativeReportOperatingSystemItem {
  name: string;
  cpe: string;
  hostCount: number;
  resultCount: number;
  vulnerabilityCount: number;
  maxSeverity: number;
  sourceReportIds: string[];
}

export interface NativeReportOperatingSystemsResponse {
  items: NativeReportOperatingSystemItem[];
  page: NativeReportPage;
}

export interface NativeReportTlsCertificateItem {
  id: string;
  fingerprintSha256: string;
  subject: string;
  issuer: string;
  serial: string;
  notBefore?: string;
  notAfter?: string;
  hostCount: number;
  portCount: number;
  resultCount: number;
  sourceReportIds: string[];
}

export interface NativeReportTlsCertificatesResponse {
  items: NativeReportTlsCertificateItem[];
  page: NativeReportPage;
}

export interface NativeReportErrorItem {
  id: string;
  host: string;
  port: string;
  nvtOid: string;
  description: string;
  sourceReportId: string;
  createdAt?: string;
}

export interface NativeReportErrorsResponse {
  items: NativeReportErrorItem[];
  page: NativeReportPage;
}

const NATIVE_PDF_REPORT_FORMAT_ID = 'c402cc3e-b531-11e1-9163-406186ea4fc5';

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

const APPLICATION_SORT_FIELDS: Record<string, string> = {
  cpe: 'cpe',
  host_count: 'host_count',
  hosts: 'host_count',
  max_severity: 'max_severity',
  name: 'name',
  occurrences: 'result_count',
  result_count: 'result_count',
  severity: 'max_severity',
  vulnerability_count: 'vulnerability_count',
};

const OPERATING_SYSTEM_SORT_FIELDS: Record<string, string> = {
  cpe: 'cpe',
  host_count: 'host_count',
  hosts: 'host_count',
  max_severity: 'max_severity',
  name: 'name',
  result_count: 'result_count',
  severity: 'max_severity',
  vulnerability_count: 'vulnerability_count',
};

const TLS_CERTIFICATE_SORT_FIELDS: Record<string, string> = {
  dn: 'subject',
  fingerprint_sha256: 'fingerprint_sha256',
  host_count: 'host_count',
  id: 'id',
  issuer: 'issuer',
  not_after: 'not_after',
  not_before: 'not_before',
  notvalidafter: 'not_after',
  notvalidbefore: 'not_before',
  port_count: 'port_count',
  result_count: 'result_count',
  serial: 'serial',
  subject: 'subject',
};

const CVE_SORT_FIELDS: Record<string, string> = {
  affected_system_count: 'affected_system_count',
  cve: 'id',
  id: 'id',
  max_severity: 'max_severity',
  result_count: 'result_count',
  severity: 'max_severity',
};

const nativeMappedSortFromFilter = (
  filter: Filter | undefined,
  fields: Record<string, string>,
  fallback: string,
): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending);
  if (rawField === '') {
    return fallback;
  }
  const nativeField = fields[rawField];
  if (nativeField === undefined) {
    return fallback;
  }
  return reverse !== undefined ? `-${nativeField}` : nativeField;
};

const nativeApplicationSortFromFilter = (filter?: Filter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending) || 'name';
  const nativeField = APPLICATION_SORT_FIELDS[rawField] ?? rawField;
  return reverse !== undefined ? `-${nativeField}` : nativeField;
};

const nativeOperatingSystemSortFromFilter = (filter?: Filter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending) || 'name';
  const nativeField = OPERATING_SYSTEM_SORT_FIELDS[rawField] ?? rawField;
  return reverse !== undefined ? `-${nativeField}` : nativeField;
};

const nativeTlsCertificateSortFromFilter = (filter?: Filter): string => {
  return nativeMappedSortFromFilter(
    filter,
    TLS_CERTIFICATE_SORT_FIELDS,
    '-not_after',
  );
};

const ERROR_SORT_FIELDS: Record<string, string> = {
  created: 'created_at',
  created_at: 'created_at',
  description: 'description',
  error: 'description',
  host: 'host',
  id: 'id',
  nvt: 'nvt_oid',
  nvt_oid: 'nvt_oid',
  port: 'port',
};

export const nativeReportApplicationsQueryFromFilter = (
  filter?: Filter,
): NativeReportQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeApplicationSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
  };
};

export const nativeReportOperatingSystemsQueryFromFilter = (
  filter?: Filter,
): NativeReportQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeOperatingSystemSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
  };
};

export const nativeReportTlsCertificatesQueryFromFilter = (
  filter?: Filter,
): NativeReportQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeTlsCertificateSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
  };
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

const nativeCveSortFromFilter = (filter?: Filter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending) || 'max_severity';
  const nativeField = CVE_SORT_FIELDS[rawField] ?? rawField;
  return reverse !== undefined ? `-${nativeField}` : nativeField;
};

const nativeErrorSortFromFilter = (filter?: Filter): string => {
  return nativeMappedSortFromFilter(filter, ERROR_SORT_FIELDS, '-created_at');
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

export const nativeReportCvesQueryFromFilter = (
  filter?: Filter,
): NativeReportQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeCveSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
  };
};

export const nativeReportErrorsQueryFromFilter = (
  filter?: Filter,
): NativeReportQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeErrorSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
  };
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

const yesNoValue = (value?: boolean): 0 | 1 => (value === true ? 1 : 0);

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
  const taskId = stringValue(filter?.get('task_id')).trim();
  const nvtOid = stringValue(filter?.get('nvt')).trim();
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeResultSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
    ...(taskId === '' ? {} : {taskId}),
    ...(nvtOid === '' ? {} : {nvtOid}),
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

export const nativeReportQueryFromFilter = (
  filter?: Filter,
): NativeReportQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  const taskId = stringValue(filter?.get('task_id')).trim();
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
    ...(taskId === '' ? {} : {taskId}),
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
  cves: stringArrayValue(item.cves),
  certRefs: stringArrayValue(item.cert_refs),
  xrefs: stringArrayValue(item.xrefs),
  descriptionExcerpt: stringValue(item.description_excerpt) || undefined,
  severity: numberValue(item.severity),
  qod: integerValue(item.qod),
  createdAt: stringValue(item.created_at) || undefined,
  sourceReportId: stringValue(item.source_report_id),
  rawEvidenceHref: stringValue(item.raw_evidence_href),
});

const nativeResultNvtTagsFromPayload = (
  item: NativeReportResultPayload,
): string => {
  const parts: string[] = [];
  const detailTags: Array<[string, unknown]> = [
    ['summary', item.summary],
    ['insight', item.insight],
    ['affected', item.affected],
    ['impact', item.impact],
    ['vuldetect', item.detection],
  ];

  for (const [key, value] of detailTags) {
    const stringified = stringValue(value);
    if (stringified !== '') {
      parts.push(`${key}=${stringified}`);
    }
  }

  return parts.join('|');
};

const nativeResultEpssFromPayload = (value?: NativeNvtEpssPayload) =>
  value
    ? {
        score: numberValue(value.score),
        percentile: numberValue(value.percentile),
        cve: {
          _id: stringValue(value.cve),
          severity: numberValue(value.severity),
        },
      }
    : undefined;

const nativeResultToModel = (item: NativeReportResultPayload): Result => {
  const solutionType = stringValue(item.solution_type);
  const solutionText = stringValue(item.solution);
  const description =
    stringValue(item.description) || stringValue(item.description_excerpt);
  const maxEpss = nativeResultEpssFromPayload(item.max_epss);
  const maxSeverity = nativeResultEpssFromPayload(item.max_severity);
  const userTags = {
    tag: (item.user_tags ?? []).map(tag => ({
      _id: stringValue(tag.id),
      name: stringValue(tag.name),
      value: stringValue(tag.value),
      comment: stringValue(tag.comment),
    })),
  };
  const overrides = {
    override: (item.overrides ?? []).map(override => ({
      _id: stringValue(override.id),
      nvt: {
        _oid: stringValue(override.nvt?.id),
        name: stringValue(override.nvt?.name),
        type: stringValue(override.nvt?.type),
      },
      text: {
        __text: stringValue(override.text),
        _excerpt: yesNoValue(override.text_excerpt),
      },
      text_excerpt: yesNoValue(override.text_excerpt),
      hosts: stringValue(override.hosts),
      port: stringValue(override.port),
      severity: override.severity ?? undefined,
      new_severity: override.new_severity ?? undefined,
      active: yesNoValue(override.active ?? true),
      end_time: stringValue(override.end_time),
      creation_time: stringValue(override.created_at),
      modification_time: stringValue(override.modified_at),
    })),
  };
  const element = {
    _id: stringValue(item.id),
    name: stringValue(item.name),
    creation_time: item.created_at,
    host: {
      __text: stringValue(item.host),
      hostname: stringValue(item.hostname),
      asset: stringValue(item.host_asset_id)
        ? {_asset_id: stringValue(item.host_asset_id)}
        : undefined,
    },
    port: stringValue(item.port),
    nvt: {
      _oid: stringValue(item.nvt_oid),
      type: 'nvt',
      name: stringValue(item.name),
      family: stringValue(item.nvt_family),
      tags: nativeResultNvtTagsFromPayload(item),
      solution:
        solutionType || solutionText
          ? {
              _type: solutionType,
              __text: solutionText,
            }
          : undefined,
      epss:
        maxEpss || maxSeverity
          ? {
              max_epss: maxEpss,
              max_severity: maxSeverity,
            }
          : undefined,
    },
    report: item.report
      ? {
          _id: stringValue(item.report.id),
          name: stringValue(item.report.name),
        }
      : {
          _id: stringValue(item.source_report_id),
        },
    task: item.task
      ? {
          _id: stringValue(item.task.id),
          name: stringValue(item.task.name),
        }
      : undefined,
    severity: numberValue(item.severity),
    qod: {value: integerValue(item.qod)},
    scan_nvt_version: stringValue(item.scan_nvt_version),
    description,
    user_tags: userTags,
    overrides,
  };
  return Result.fromElement(
    element as unknown as Parameters<typeof Result.fromElement>[0],
  );
};

const nativeReportApplicationFromPayload = (
  item: NativeReportApplicationPayload,
): NativeReportApplicationItem => ({
  name: stringValue(item.name),
  version: stringValue(item.version),
  cpe: stringValue(item.cpe),
  hostCount: integerValue(item.host_count),
  resultCount: integerValue(item.result_count),
  vulnerabilityCount: integerValue(item.vulnerability_count),
  maxSeverity: numberValue(item.max_severity),
  sourceReportIds: stringArrayValue(item.source_report_ids),
});

const nativeReportOperatingSystemFromPayload = (
  item: NativeReportOperatingSystemPayload,
): NativeReportOperatingSystemItem => ({
  name: stringValue(item.name),
  cpe: stringValue(item.cpe),
  hostCount: integerValue(item.host_count),
  resultCount: integerValue(item.result_count),
  vulnerabilityCount: integerValue(item.vulnerability_count),
  maxSeverity: numberValue(item.max_severity),
  sourceReportIds: stringArrayValue(item.source_report_ids),
});

const nativeReportTlsCertificateFromPayload = (
  item: NativeReportTlsCertificatePayload,
): NativeReportTlsCertificateItem => ({
  id: stringValue(item.id),
  fingerprintSha256: stringValue(item.fingerprint_sha256),
  subject: stringValue(item.subject),
  issuer: stringValue(item.issuer),
  serial: stringValue(item.serial),
  notBefore: stringValue(item.not_before) || undefined,
  notAfter: stringValue(item.not_after) || undefined,
  hostCount: integerValue(item.host_count),
  portCount: integerValue(item.port_count),
  resultCount: integerValue(item.result_count),
  sourceReportIds: stringArrayValue(item.source_report_ids),
});

const stringArrayValue = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter(item => typeof item === 'string') : [];

const nativeReportCveFromPayload = (
  item: NativeReportCvePayload,
): NativeReportCveItem => ({
  id: stringValue(item.id),
  affectedSystemCount: integerValue(item.affected_system_count),
  resultCount: integerValue(item.result_count),
  maxSeverity: numberValue(item.max_severity),
  sourceReportIds: stringArrayValue(item.source_report_ids),
});

const nativeReportErrorFromPayload = (
  item: NativeReportErrorPayload,
): NativeReportErrorItem => ({
  id: stringValue(item.id),
  host: stringValue(item.host),
  port: stringValue(item.port),
  nvtOid: stringValue(item.nvt_oid),
  description: stringValue(item.description),
  sourceReportId: stringValue(item.source_report_id),
  createdAt: stringValue(item.created_at) || undefined,
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

const nativeFilterElement = (filter?: Filter) =>
  filter === undefined ? undefined : {term: filter.toFilterString()};

export const nativeReportToModel = (
  item: NativeReportItem,
  reportFilter?: Filter,
): Report => {
  const progress =
    typeof item.progress === 'number'
      ? integerValue(item.progress)
      : item.status === 'Done'
        ? 100
        : undefined;
  const task = item.task
    ? {
        _id: item.task.id,
        name: item.task.name,
        progress,
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
  const owner = {name: stringValue(item.owner?.name)};
  const userTags = {
    tag: (item.user_tags ?? []).map(tag => ({
      _id: stringValue(tag.id),
      name: stringValue(tag.name),
      value: stringValue(tag.value),
      comment: stringValue(tag.comment),
    })),
  };
  const filters = nativeFilterElement(reportFilter);
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
      owner,
      user_tags: userTags,
      filters,
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
    owner,
    user_tags: userTags,
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

const fetchNativePdf = async (
  gmp: NativeApiGmp,
  path: string,
  params: UrlParams,
): Promise<ArrayBuffer> => {
  const response = await fetch(gmp.buildUrl(path, params), {
    credentials: 'include',
    headers: {
      Accept: 'application/pdf',
      ...(gmp.session.jwt ? {Authorization: `Bearer ${gmp.session.jwt}`} : {}),
    },
  });
  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }
  return response.arrayBuffer();
};

export const fetchNativeReport = async (
  gmp: NativeApiGmp,
  id: string,
  filter?: Filter,
): Promise<NativeReportResponse> => {
  const payload = await fetchNativeJson<NativeReportDetailPayload>(
    gmp,
    `api/v1/reports/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return {report: nativeReportToModel(payload, filter)};
};

export const fetchNativeReportPdf = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<ArrayBuffer> => {
  return fetchNativePdf(
    gmp,
    `api/v1/reports/${encodeURIComponent(id)}/download`,
    {
      token: gmp.session.token,
      report_format_id: NATIVE_PDF_REPORT_FORMAT_ID,
    },
  );
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
      ...(query.taskId === undefined ? {} : {task_id: query.taskId}),
    },
  );
  const page = {
    page: integerValue(payload.page?.page, 1),
    page_size: integerValue(payload.page?.page_size, query.pageSize),
    total: integerValue(payload.page?.total),
    sort: stringValue(payload.page?.sort),
    filter: stringValue(payload.page?.filter),
  };
  const reports = (payload.items ?? []).map(item => nativeReportToModel(item));
  return {
    reports,
    counts: nativeCounts(page, reports.length),
    page,
  };
};

export const fetchNativeResults = async (
  gmp: NativeApiGmp,
  query: NativeReportQuery,
): Promise<NativeResultsResponse> => {
  const payload = await fetchNativeJson<NativeReportResultsPayload>(
    gmp,
    'api/v1/results',
    {
      token: gmp.session.token,
      page: query.page,
      page_size: query.pageSize,
      sort: query.sort,
      filter: query.filter,
      ...(query.taskId === undefined ? {} : {task_id: query.taskId}),
      ...(query.nvtOid === undefined ? {} : {nvt_oid: query.nvtOid}),
    },
  );
  const page = {
    page: integerValue(payload.page?.page, 1),
    page_size: integerValue(payload.page?.page_size, query.pageSize),
    total: integerValue(payload.page?.total),
    sort: stringValue(payload.page?.sort),
    filter: stringValue(payload.page?.filter),
  };
  const results = (payload.items ?? []).map(nativeResultToModel);
  return {
    results,
    counts: nativeCounts(page, results.length),
    page,
  };
};

export const fetchNativeResult = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<NativeResultResponse> => {
  const payload = await fetchNativeJson<NativeReportResultPayload>(
    gmp,
    `api/v1/results/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return {result: nativeResultToModel(payload)};
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

export const fetchNativeReportCves = async (
  gmp: NativeApiGmp,
  reportId: string,
  query: NativeReportQuery,
): Promise<NativeReportCvesResponse> => {
  const payload = await fetchNativeJson<NativeReportCvesPayload>(
    gmp,
    `api/v1/reports/${encodeURIComponent(reportId)}/cves`,
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
    items: (payload.items ?? []).map(nativeReportCveFromPayload),
    page,
  };
};

export const fetchNativeReportErrors = async (
  gmp: NativeApiGmp,
  reportId: string,
  query: NativeReportQuery,
): Promise<NativeReportErrorsResponse> => {
  const payload = await fetchNativeJson<NativeReportErrorsPayload>(
    gmp,
    `api/v1/reports/${encodeURIComponent(reportId)}/errors`,
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
    items: (payload.items ?? []).map(nativeReportErrorFromPayload),
    page,
  };
};

export const fetchNativeReportApplications = async (
  gmp: NativeApiGmp,
  reportId: string,
  query: NativeReportQuery,
): Promise<NativeReportApplicationsResponse> => {
  const payload = await fetchNativeJson<NativeReportApplicationsPayload>(
    gmp,
    `api/v1/reports/${encodeURIComponent(reportId)}/applications`,
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
    items: (payload.items ?? []).map(nativeReportApplicationFromPayload),
    page,
  };
};

export const fetchNativeReportOperatingSystems = async (
  gmp: NativeApiGmp,
  reportId: string,
  query: NativeReportQuery,
): Promise<NativeReportOperatingSystemsResponse> => {
  const payload = await fetchNativeJson<NativeReportOperatingSystemsPayload>(
    gmp,
    `api/v1/reports/${encodeURIComponent(reportId)}/operating-systems`,
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
    items: (payload.items ?? []).map(nativeReportOperatingSystemFromPayload),
    page,
  };
};

export const fetchNativeReportTlsCertificates = async (
  gmp: NativeApiGmp,
  reportId: string,
  query: NativeReportQuery,
): Promise<NativeReportTlsCertificatesResponse> => {
  const payload = await fetchNativeJson<NativeReportTlsCertificatesPayload>(
    gmp,
    `api/v1/reports/${encodeURIComponent(reportId)}/tls-certificates`,
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
    items: (payload.items ?? []).map(nativeReportTlsCertificateFromPayload),
    page,
  };
};
