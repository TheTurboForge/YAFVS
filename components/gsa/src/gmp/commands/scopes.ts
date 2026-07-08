/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import HttpCommand from 'gmp/commands/http';
import type {EntitiesMeta} from 'gmp/commands/entities';
import {
  canUseNativeApi,
  filterFromCommandParams,
  nativeCollectionMeta,
} from 'gmp/commands/native';
import {getMetricsNode, parseReportMetrics} from 'gmp/commands/report-metrics';
import type {ReportMetrics} from 'gmp/commands/report-metrics';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import type {XmlResponseData} from 'gmp/http/transform/fast-xml';
import Filter from 'gmp/models/filter';
import {
  createNativeScope,
  deleteNativeScope,
  fetchNativeScope,
  fetchNativeScopes,
  patchNativeScope,
} from 'gmp/native-api/scopes';
import {
  canUseNativeScopeReportList,
  deleteNativeScopeReport,
  fetchNativeScopeReport,
  fetchNativeScopeReports,
  nativeScopeReportQueryFromFilter,
} from 'gmp/native-api/scope-reports';
import {isDefined} from 'gmp/utils/identity';

export type ProtectionRequirement = 'normal' | 'high' | 'very_high';

export interface ScopeTarget {
  id: string;
  name: string;
}

export interface ScopeHost {
  id: string;
  name: string;
}

export interface ScopeCandidateHost extends ScopeHost {
  targetId?: string;
  targetName?: string;
  sourceReportId?: string;
}

export interface ScopeReportSummary {
  id: string;
  name: string;
  created?: string;
  latestEvidenceTime?: string;
  sourceReportCount: number;
  hostsTotal: number;
  hostsWithEvidence: number;
  hostsMissingEvidence: number;
  resultsTotal: number;
  vulnerabilitiesTotal: number;
  severityHigh: number;
  severityMedium: number;
  severityLow: number;
  severityLog: number;
  severityFalsePositive: number;
  maxSeverity: number;
  excludedCandidateHosts: number;
  metricsSummary?: ScopeReportMetricsSummary;
}

export interface ScopeReportMetricsSummary {
  totalSystemCvssLoad: number;
  averageSystemCvssLoad: number;
  authenticatedScanCoveragePercent: number;
  aliveSystemCount: number;
  vulnerabilityCount: number;
  authenticatedSystemCount: number;
  authenticationFailedSystemCount: number;
  noCredentialPathSystemCount: number;
  unknownAuthenticationSystemCount: number;
}

export interface Scope {
  id: string;
  name: string;
  comment?: string;
  protectionRequirement: ProtectionRequirement;
  protectionRequirementLabel: string;
  predefined: boolean;
  global: boolean;
  creationTime?: string;
  modificationTime?: string;
  targetCount: number;
  hostCount: number;
  scopeReportCount: number;
  targets: ScopeTarget[];
  hosts: ScopeHost[];
  candidateHosts: ScopeCandidateHost[];
  scopeReports: ScopeReportSummary[];
}

export interface ScopeReportSource {
  id?: string;
  sourceReportId?: string;
  sourceReportName?: string;
  targetId?: string;
  targetName?: string;
  taskId?: string;
  taskName?: string;
  scanEnd?: string;
  selected: boolean;
  reason?: string;
}

export interface ScopeReportResult {
  id?: string;
  sourceReportId?: string;
  host?: string;
  port?: string;
  nvtOid?: string;
  nvtName?: string;
  severity: number;
  severityLabel?: string;
  qod?: number;
  created?: string;
}

export interface ScopeReport extends ScopeReportSummary {
  scopeId: string;
  scopeName: string;
  protectionRequirement: ProtectionRequirement;
  protectionRequirementLabel: string;
  sources: ScopeReportSource[];
  topResults: ScopeReportResult[];
}

type XmlNode = Record<string, unknown>;

interface ScopeWriteParams {
  id?: string;
  name?: string;
  comment?: string;
  protectionRequirement?: ProtectionRequirement | string;
  targetIds?: string[];
  hostIds?: string[];
}

interface ScopeModifyNativeParams extends ScopeWriteParams {
  id: string;
}

const SCOPE_MODIFY_KEYS = new Set([
  'id',
  'name',
  'comment',
  'protectionRequirement',
  'targetIds',
  'hostIds',
]);

const SCOPE_CREATE_KEYS = new Set([
  'name',
  'comment',
  'protectionRequirement',
  'targetIds',
  'hostIds',
]);

const isStringArray = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every(item => typeof item === 'string');

const isNativeScopeModify = (
  params: ScopeWriteParams,
): params is ScopeModifyNativeParams => {
  const keys = Object.keys(params);
  return (
    keys.every(key => SCOPE_MODIFY_KEYS.has(key)) &&
    typeof params.id === 'string' &&
    (params.name === undefined || typeof params.name === 'string') &&
    (params.comment === undefined || typeof params.comment === 'string') &&
    (params.protectionRequirement === undefined ||
      typeof params.protectionRequirement === 'string') &&
    (params.targetIds === undefined || isStringArray(params.targetIds)) &&
    (params.hostIds === undefined || isStringArray(params.hostIds))
  );
};

const isNativeScopeCreate = (
  params: ScopeWriteParams,
): params is ScopeWriteParams & {name: string} => {
  const keys = Object.keys(params);
  return (
    keys.every(key => SCOPE_CREATE_KEYS.has(key)) &&
    typeof params.name === 'string' &&
    (params.comment === undefined || typeof params.comment === 'string') &&
    (params.protectionRequirement === undefined ||
      typeof params.protectionRequirement === 'string') &&
    (params.targetIds === undefined || isStringArray(params.targetIds)) &&
    (params.hostIds === undefined || isStringArray(params.hostIds))
  );
};

const asArray = <T>(value: T | T[] | undefined): T[] => {
  if (!isDefined(value)) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
};

const getNode = (node: unknown): XmlNode => {
  if (typeof node === 'object' && node !== null) {
    return node as XmlNode;
  }
  return {};
};

const text = (node: unknown, fallback = ''): string => {
  if (!isDefined(node)) {
    return fallback;
  }
  if (typeof node === 'string' || typeof node === 'number') {
    return String(node);
  }
  const data = getNode(node);
  if (isDefined(data.__text)) {
    return String(data.__text);
  }
  return fallback;
};

const optionalText = (node: unknown): string | undefined => {
  const value = text(node);
  return value === '' ? undefined : value;
};

const bool = (node: unknown): boolean => {
  const value = text(node, '0').toLowerCase();
  return value === '1' || value === 'true' || value === 'yes';
};

const integer = (node: unknown): number => {
  const value = Number.parseInt(text(node, '0'), 10);
  return Number.isFinite(value) ? value : 0;
};

const decimal = (node: unknown): number => {
  const value = Number.parseFloat(text(node, '0'));
  return Number.isFinite(value) ? value : 0;
};

const idOf = (node: unknown): string => {
  const data = getNode(node);
  return text(data._id, text(data.id));
};

const protectionValue = (data: XmlNode): ProtectionRequirement => {
  const protection = getNode(data.protection_requirement);
  return text(
    protection.value,
    text(data.protection_requirement, 'normal'),
  ) as ProtectionRequirement;
};

const protectionLabel = (data: XmlNode): string => {
  const protection = getNode(data.protection_requirement);
  return text(
    protection.label,
    text(data.protection_requirement_label, 'Normal'),
  );
};

const countValue = (
  counts: XmlNode,
  data: XmlNode,
  nested: string,
  flat: string,
) => integer(counts[nested] ?? data[flat]);

const parseScopeReportSummary = (node: unknown): ScopeReportSummary => {
  const data = getNode(node);
  const counts = getNode(data.counts);
  const severity = getNode(counts.severity ?? data.severity);
  return {
    id: idOf(data),
    name: text(data.name),
    created: optionalText(data.created ?? data.creation_time),
    latestEvidenceTime: optionalText(data.latest_evidence_time),
    sourceReportCount: countValue(
      counts,
      data,
      'source_reports',
      'source_report_count',
    ),
    hostsTotal: countValue(counts, data, 'hosts_total', 'member_host_count'),
    hostsWithEvidence: countValue(
      counts,
      data,
      'hosts_with_evidence',
      'evidence_host_count',
    ),
    hostsMissingEvidence: countValue(
      counts,
      data,
      'hosts_missing_evidence',
      'missing_host_count',
    ),
    resultsTotal: countValue(counts, data, 'results_total', 'result_count'),
    vulnerabilitiesTotal: countValue(
      counts,
      data,
      'vulnerabilities_total',
      'vulnerability_count',
    ),
    severityHigh: integer(severity.high),
    severityMedium: integer(severity.medium),
    severityLow: integer(severity.low),
    severityLog: integer(severity.log),
    severityFalsePositive: integer(severity.false_positive),
    maxSeverity: decimal(data.max_severity),
    excludedCandidateHosts: countValue(
      counts,
      data,
      'excluded_candidate_hosts',
      'excluded_candidate_host_count',
    ),
  };
};

const parseScopeReport = (node: unknown): ScopeReport => {
  const data = getNode(node);
  const summary = parseScopeReportSummary(data);
  const scope = getNode(data.scope);
  const sources = getNode(data.sources);
  const results = getNode(data.top_results ?? data.results);
  return {
    ...summary,
    scopeId: idOf(scope),
    scopeName: text(scope.name),
    protectionRequirement: protectionValue(data),
    protectionRequirementLabel: protectionLabel(data),
    sources: asArray(sources.source).map(source => {
      const sourceData = getNode(source);
      const report = getNode(sourceData.source_report);
      const target = getNode(sourceData.target);
      const task = getNode(sourceData.task);
      return {
        id: idOf(sourceData),
        sourceReportId: idOf(report) || optionalText(sourceData._report_id),
        sourceReportName: optionalText(report.name),
        targetId: idOf(target) || optionalText(sourceData._target_id),
        targetName: optionalText(target.name ?? sourceData.target_name),
        taskId: idOf(task) || optionalText(sourceData._task_id),
        taskName: optionalText(task.name ?? sourceData.task_name),
        scanEnd: optionalText(sourceData.scan_end),
        selected: true,
        reason: optionalText(sourceData.reason),
      };
    }),
    topResults: asArray(results.result).map(result => {
      const resultData = getNode(result);
      const nvt = getNode(resultData.nvt);
      const sourceReportId = optionalText(resultData._source_report_id);
      return {
        id: idOf(resultData),
        sourceReportId,
        host: optionalText(resultData.host),
        port: optionalText(resultData.port),
        nvtOid: optionalText(nvt.oid) ?? optionalText(resultData.nvt),
        nvtName: optionalText(nvt.name) ?? optionalText(resultData.nvt),
        severity: decimal(resultData.severity),
        severityLabel: optionalText(resultData.severity_label),
        qod: integer(resultData.qod),
        created: optionalText(resultData.created ?? resultData.date),
      };
    }),
  };
};

const listPostParam = (values?: string[]) => {
  if (!isDefined(values)) {
    return undefined;
  }
  return values.join(' ');
};

const responseRoot = (root: XmlResponseData, name: string): XmlNode => {
  return getNode(getNode(root[name])[`${name}_response`]);
};

const parseScopeReportCounts = (
  root: XmlNode,
  reports: XmlNode,
  reportCount: number,
) => {
  const count = getNode(root.scope_report_count);
  return new CollectionCounts({
    first: integer(reports._start),
    rows: integer(reports._max),
    length: integer(count.page) || reportCount,
    all: integer(count.__text) || reportCount,
    filtered: integer(count.filtered) || reportCount,
  });
};

const parseScopeReportFilter = (root: XmlNode) => {
  const filters = getNode(root.filters);
  return Filter.fromString(text(filters.term));
};

export class ScopesCommand extends HttpCommand {
  constructor(http: Http) {
    super(http, {cmd: 'get_scopes'});
  }

  async get({id, details: _details}: {id?: string; details?: number} = {}) {
    if (id !== undefined) {
      const scope = await fetchNativeScope(this.http, id);
      return new Response<Scope[]>(scope === undefined ? [] : [scope]);
    }
    return new Response<Scope[]>(await fetchNativeScopes(this.http));
  }

  async getOne(id: string) {
    return new Response<Scope | undefined>(await fetchNativeScope(this.http, id));
  }

  create(params: ScopeWriteParams) {
    if (canUseNativeApi(this.http) && isNativeScopeCreate(params)) {
      return createNativeScope(this.http, params);
    }

    return this.httpPostWithTransform({
      cmd: 'create_scope',
      name: params.name,
      comment: params.comment,
      protection_requirement: params.protectionRequirement,
      target_ids: listPostParam(params.targetIds),
      host_ids: listPostParam(params.hostIds),
    });
  }

  modify(params: ScopeWriteParams) {
    if (canUseNativeApi(this.http) && isNativeScopeModify(params)) {
      return patchNativeScope(this.http, params);
    }

    return this.httpPostWithTransform({
      cmd: 'modify_scope',
      scope_id: params.id,
      name: params.name,
      comment: params.comment,
      protection_requirement: params.protectionRequirement,
      target_ids: listPostParam(params.targetIds),
      host_ids: listPostParam(params.hostIds),
    });
  }

  async delete({id}: {id: string}) {
    if (canUseNativeApi(this.http)) {
      await deleteNativeScope(this.http, id);
      return;
    }

    return this.httpPostWithTransform({cmd: 'delete_scope', scope_id: id});
  }

  generateReport({id}: {id: string}) {
    return this.httpPostWithTransform({
      cmd: 'generate_scope_report',
      scope_id: id,
    });
  }
}

export class ScopeReportsCommand extends HttpCommand {
  constructor(http: Http) {
    super(http, {cmd: 'get_scope_reports'});
  }

  async get({
    id,
    scopeId,
    filter,
    details = 1,
  }: {
    id?: string;
    scopeId?: string;
    filter?: Filter | string;
    details?: number;
  } = {}) {
    if (canUseNativeApi(this.http)) {
      const nativeFilter = filterFromCommandParams({filter});
      if (id !== undefined) {
        const report = await fetchNativeScopeReport(this.http, id);
        return new Response<ScopeReport[], EntitiesMeta>([report], {
          filter: nativeFilter,
          counts: nativeCollectionMeta(nativeFilter, [report], 1).counts,
        });
      }
      if (canUseNativeScopeReportList(nativeFilter, scopeId)) {
        const nativeResponse = await fetchNativeScopeReports(
          this.http,
          nativeScopeReportQueryFromFilter(nativeFilter, scopeId),
        );
        return new Response<ScopeReport[], EntitiesMeta>(
          nativeResponse.reports,
          {
            filter: nativeFilter,
            counts: nativeResponse.counts,
          },
        );
      }
    }

    const response = await this.httpGetWithTransform({
      scope_report_id: id,
      scope_id: scopeId,
      filter,
      details,
    });
    const root = responseRoot(response.data, 'get_scope_reports');
    const reports = getNode(root.scope_reports);
    const parsed = asArray(reports.scope_report).map(parseScopeReport);
    return response.set<ScopeReport[], EntitiesMeta>(parsed, {
      filter: parseScopeReportFilter(root),
      counts: parseScopeReportCounts(root, reports, parsed.length),
    });
  }

  async getOne(id: string) {
    const response = await this.get({id, details: 1});
    return response.set<ScopeReport | undefined>(response.data[0]);
  }

  async getMetrics(id: string) {
    const response = await this.httpGetWithTransform(
      {cmd: 'get_scope_report_metrics', scope_report_id: id},
      {includeDefaultParams: false},
    );
    const metrics = parseReportMetrics(
      getMetricsNode(
        response.data,
        'get_scope_report_metrics',
        'scope_report_metrics',
      ),
    );
    return response.set<ReportMetrics>(metrics);
  }

  async delete({id}: {id: string}) {
    if (canUseNativeApi(this.http)) {
      await deleteNativeScopeReport(this.http, id);
      return;
    }

    return this.httpPostWithTransform({
      cmd: 'delete_scope_report',
      scope_report_id: id,
    });
  }
}
