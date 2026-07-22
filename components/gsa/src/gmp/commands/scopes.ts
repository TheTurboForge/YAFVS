/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type {EntitiesMeta} from 'gmp/commands/entities';
import {
  filterFromCommandParams,
  nativeCollectionMeta,
} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import type Filter from 'gmp/models/filter';
import {
  deleteNativeScopeReport,
  fetchNativeScopeReport,
  fetchNativeScopeReports,
  generateNativeScopeReport,
  nativeScopeReportQueryFromFilter,
} from 'gmp/native-api/scope-reports';
import {
  createNativeScope,
  deleteNativeScope,
  fetchNativeScope,
  fetchNativeScopes,
  patchNativeScope,
} from 'gmp/native-api/scopes';

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

export class ScopesCommand {
  private readonly http: Http;

  constructor(http: Http) {
    this.http = http;
  }

  async get({id, details: _details}: {id?: string; details?: number} = {}) {
    if (id !== undefined) {
      const scope = await fetchNativeScope(this.http, id);
      return new Response<Scope[]>(scope === undefined ? [] : [scope]);
    }
    return new Response<Scope[]>(await fetchNativeScopes(this.http));
  }

  async getOne(id: string) {
    return new Response<Scope | undefined>(
      await fetchNativeScope(this.http, id),
    );
  }

  create(params: ScopeWriteParams) {
    if (isNativeScopeCreate(params)) {
      return createNativeScope(this.http, params);
    }
    throw new Error('Native scope create received unsupported payload shape');
  }

  modify(params: ScopeWriteParams) {
    if (isNativeScopeModify(params)) {
      return patchNativeScope(this.http, params);
    }
    throw new Error('Native scope modify received unsupported payload shape');
  }

  async delete({id}: {id: string}) {
    await deleteNativeScope(this.http, id);
  }

  generateReport({id}: {id: string}) {
    return generateNativeScopeReport(this.http, id);
  }
}

export class ScopeReportsCommand {
  private readonly http: Http;

  constructor(http: Http) {
    this.http = http;
  }

  async get({
    id,
    scopeId,
    filter,
    details: _details = 1,
  }: {
    id?: string;
    scopeId?: string;
    filter?: Filter | string;
    details?: number;
  } = {}) {
    const nativeFilter = filterFromCommandParams({filter});
    if (id !== undefined) {
      const report = await fetchNativeScopeReport(this.http, id);
      return new Response<ScopeReport[], EntitiesMeta>([report], {
        filter: nativeFilter,
        counts: nativeCollectionMeta(nativeFilter, [report], 1).counts,
      });
    }
    const nativeResponse = await fetchNativeScopeReports(
      this.http,
      nativeScopeReportQueryFromFilter(nativeFilter, scopeId),
    );
    return new Response<ScopeReport[], EntitiesMeta>(nativeResponse.reports, {
      filter: nativeFilter,
      counts: nativeResponse.counts,
    });
  }

  async getOne(id: string) {
    const response = await this.get({id, details: 1});
    return response.set<ScopeReport | undefined>(response.data[0]);
  }

  async delete({id}: {id: string}) {
    await deleteNativeScopeReport(this.http, id);
  }
}
