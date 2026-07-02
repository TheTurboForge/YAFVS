/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type {
  ProtectionRequirement,
  Scope,
  ScopeCandidateHost,
  ScopeHost,
  ScopeReportSummary,
  ScopeTarget,
} from 'gmp/commands/scopes';
import Response from 'gmp/http/response';
import type {UrlParams} from 'gmp/http/utils';

interface NativeApiSession {
  readonly jwt?: string;
  readonly token?: string;
}

interface NativeApiGmp {
  readonly session: NativeApiSession;
  buildUrl(path: string, params?: UrlParams): string;
}

interface NativeScopeEntity {
  id?: string;
  name?: string;
}

interface NativeScopeCandidateHost extends NativeScopeEntity {
  target_id?: string;
  target_name?: string;
  source_report_id?: string;
}

interface NativeScopeReportReference {
  id?: string;
  name?: string;
  creation_time?: string;
  latest_evidence_time?: string;
  source_report_count?: number;
  member_host_count?: number;
  evidence_host_count?: number;
  missing_host_count?: number;
  result_count?: number;
  vulnerability_count?: number;
  max_severity?: number;
}

interface NativeScopeItem {
  id?: string;
  name?: string;
  comment?: string;
  protection_requirement?: ProtectionRequirement | string;
  protection_requirement_label?: string;
  predefined?: boolean;
  global?: boolean;
  creation_time?: string;
  modification_time?: string;
  target_count?: number;
  host_count?: number;
  scope_report_count?: number;
  targets?: NativeScopeEntity[];
  hosts?: NativeScopeEntity[];
  candidate_hosts?: NativeScopeCandidateHost[];
  scope_reports?: NativeScopeReportReference[];
}

interface NativeScopeCollectionPayload {
  items?: NativeScopeItem[];
}

interface NativeScopePatchArgs {
  id: string;
  name?: string;
  comment?: string;
  protectionRequirement?: ProtectionRequirement | string;
  targetIds?: string[];
  hostIds?: string[];
}

interface NativeScopeCreateArgs {
  name: string;
  comment?: string;
  protectionRequirement?: ProtectionRequirement | string;
  targetIds?: string[];
  hostIds?: string[];
}

const stringValue = (value: unknown, fallback = ''): string =>
  typeof value === 'string' ? value : fallback;

const optionalStringValue = (value: unknown): string | undefined =>
  typeof value === 'string' && value.length > 0 ? value : undefined;

const integerValue = (value: unknown): number => {
  const parsed =
    typeof value === 'number' ? value : Number.parseInt(String(value ?? 0), 10);
  return Number.isFinite(parsed) ? parsed : 0;
};

const numberValue = (value: unknown): number => {
  const parsed =
    typeof value === 'number' ? value : Number.parseFloat(String(value ?? 0));
  return Number.isFinite(parsed) ? parsed : 0;
};

const asArray = <T,>(value: T[] | undefined): T[] =>
  Array.isArray(value) ? value : [];

const entity = (item: NativeScopeEntity): ScopeTarget | ScopeHost => ({
  id: stringValue(item.id),
  name: stringValue(item.name, stringValue(item.id)),
});

const candidateHost = (item: NativeScopeCandidateHost): ScopeCandidateHost => ({
  id: stringValue(item.id, stringValue(item.name)),
  name: stringValue(item.name, stringValue(item.id)),
  targetId: optionalStringValue(item.target_id),
  targetName: optionalStringValue(item.target_name),
  sourceReportId: optionalStringValue(item.source_report_id),
});

const scopeReportReference = (
  item: NativeScopeReportReference,
): ScopeReportSummary => ({
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
  severityHigh: 0,
  severityMedium: 0,
  severityLow: 0,
  severityLog: 0,
  severityFalsePositive: 0,
  maxSeverity: numberValue(item.max_severity),
  excludedCandidateHosts: 0,
});

export const nativeScopeToModel = (item: NativeScopeItem): Scope => ({
  id: stringValue(item.id),
  name: stringValue(item.name),
  comment: optionalStringValue(item.comment),
  protectionRequirement: stringValue(
    item.protection_requirement,
    'normal',
  ) as ProtectionRequirement,
  protectionRequirementLabel: stringValue(
    item.protection_requirement_label,
    'Normal',
  ),
  predefined: item.predefined === true,
  global: item.global === true,
  creationTime: optionalStringValue(item.creation_time),
  modificationTime: optionalStringValue(item.modification_time),
  targetCount: integerValue(item.target_count),
  hostCount: integerValue(item.host_count),
  scopeReportCount: integerValue(item.scope_report_count),
  targets: asArray(item.targets).map(entity),
  hosts: asArray(item.hosts).map(entity),
  candidateHosts: asArray(item.candidate_hosts).map(candidateHost),
  scopeReports: asArray(item.scope_reports).map(scopeReportReference),
});

const fetchNativeJson = async <T>(
  gmp: NativeApiGmp,
  path: string,
  params?: UrlParams,
): Promise<T> => {
  const headers: HeadersInit = {Accept: 'application/json'};
  if (gmp.session.jwt) {
    headers.Authorization = `Bearer ${gmp.session.jwt}`;
  }
  const response = await fetch(
    gmp.buildUrl(path, {
      token: gmp.session.token,
      ...params,
    }),
    {
      credentials: 'include',
      headers,
    },
  );
  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }
  return (await response.json()) as T;
};

const writeNativeJson = async <T>(
  gmp: NativeApiGmp,
  path: string,
  body: unknown,
  method = 'POST',
): Promise<T> => {
  const response = await fetch(gmp.buildUrl(path), {
    method,
    credentials: 'include',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...(gmp.session.token ? {'X-TurboVAS-Token': gmp.session.token} : {}),
      ...(gmp.session.jwt ? {Authorization: `Bearer ${gmp.session.jwt}`} : {}),
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }

  return (await response.json()) as T;
};

export const fetchNativeScopes = async (gmp: NativeApiGmp): Promise<Scope[]> => {
  const payload = await fetchNativeJson<NativeScopeCollectionPayload>(
    gmp,
    'api/v1/scopes',
    {
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: '',
    },
  );
  return asArray(payload.items).map(nativeScopeToModel);
};

export const fetchNativeScope = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Scope | undefined> => {
  const payload = await fetchNativeJson<NativeScopeItem>(
    gmp,
    `api/v1/scopes/${encodeURIComponent(id)}`,
  );
  return nativeScopeToModel(payload);
};

export const createNativeScope = async (
  gmp: NativeApiGmp,
  {
    name,
    comment,
    protectionRequirement,
    targetIds,
    hostIds,
  }: NativeScopeCreateArgs,
): Promise<Response<{id: string}>> => {
  const body = {
    name,
    ...(comment !== undefined ? {comment} : {}),
    ...(protectionRequirement !== undefined
      ? {protection_requirement: protectionRequirement}
      : {}),
    ...(targetIds !== undefined ? {target_ids: targetIds} : {}),
    ...(hostIds !== undefined ? {host_ids: hostIds} : {}),
  };
  const payload = await writeNativeJson<NativeScopeItem>(
    gmp,
    'api/v1/scopes',
    body,
  );
  return new Response({id: stringValue(payload.id)});
};

export const patchNativeScope = async (
  gmp: NativeApiGmp,
  {
    id,
    name,
    comment,
    protectionRequirement,
    targetIds,
    hostIds,
  }: NativeScopePatchArgs,
): Promise<Response<{id: string}>> => {
  const body = {
    ...(name !== undefined ? {name} : {}),
    ...(comment !== undefined ? {comment} : {}),
    ...(protectionRequirement !== undefined
      ? {protection_requirement: protectionRequirement}
      : {}),
    ...(targetIds !== undefined ? {target_ids: targetIds} : {}),
    ...(hostIds !== undefined ? {host_ids: hostIds} : {}),
  };
  const payload = await writeNativeJson<NativeScopeItem>(
    gmp,
    `api/v1/scopes/${encodeURIComponent(id)}`,
    body,
    'PATCH',
  );
  return new Response({id: stringValue(payload.id)});
};
