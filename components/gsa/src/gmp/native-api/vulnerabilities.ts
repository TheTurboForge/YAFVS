/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import Response from 'gmp/http/response';
import type {UrlParams} from 'gmp/http/utils';
import type Filter from 'gmp/models/filter';
import Vulnerability from 'gmp/models/vulnerability';

interface NativeApiSession {
  readonly jwt?: string;
  readonly token?: string;
}

interface NativeApiGmp {
  readonly session: NativeApiSession;
  buildUrl(path: string, params?: UrlParams): string;
}

interface NativePage {
  page: number;
  page_size: number;
  total: number;
  sort: string;
  filter: string;
}

interface NativeVulnerabilityPayload {
  id: string;
  name: string;
  family?: string;
  oldest_result?: string;
  newest_result?: string;
  severity: number;
  qod: number;
  result_count: number;
  host_count: number;
  cves?: string[];
  cert_refs?: string[];
  xrefs?: string[];
  max_epss?: NativeNvtEpssPayload;
  max_severity?: NativeNvtEpssPayload;
  summary?: string;
  insight?: string;
  affected?: string;
  impact?: string;
  detection?: string;
  solution_type?: string;
  solution?: string;
}

interface NativeNvtEpssPayload {
  score?: number;
  percentile?: number;
  cve?: string;
  severity?: number;
}

interface NativeVulnerabilitiesPayload {
  page?: Partial<NativePage>;
  items?: NativeVulnerabilityPayload[];
}

export interface NativeVulnerabilityQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
  vulnerabilityId?: string;
}

export interface NativeVulnerabilitiesResponse {
  vulnerabilities: Vulnerability[];
  counts: CollectionCounts;
  page: NativePage;
}

const VULNERABILITY_SORT_FIELDS: Record<string, string> = {
  name: 'name',
  oldest: 'oldest',
  newest: 'newest',
  severity: 'severity',
  qod: 'qod',
  results: 'results',
  hosts: 'hosts',
};

const stringValue = (value: unknown): string =>
  typeof value === 'string' ? value : '';

const integerValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const numberValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseFloat(String(value ?? fallback));
  return Number.isFinite(parsed) ? parsed : fallback;
};

const refPartsFromNative = (value: string) => {
  const separator = value.indexOf(':');
  if (separator <= 0) {
    return {type: 'other', value};
  }
  return {type: value.slice(0, separator), value: value.slice(separator + 1)};
};

const certFromNative = (value: string) => {
  const parts = refPartsFromNative(value);
  return {type: parts.type, id: parts.value};
};

const xrefFromNative = (value: string) => {
  const parts = refPartsFromNative(value);
  return {type: parts.type, ref: parts.value};
};

const epssFromNative = (value?: NativeNvtEpssPayload) =>
  value
    ? {
        score: numberValue(value.score),
        percentile: numberValue(value.percentile),
        cve: {
          id: stringValue(value.cve),
          severity: numberValue(value.severity),
        },
      }
    : undefined;

const nativeSortFromFilter = (filter?: Filter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending) || 'severity';
  const nativeField = VULNERABILITY_SORT_FIELDS[rawField] ?? rawField;
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

export const nativeVulnerabilitiesQueryFromFilter = (
  filter?: Filter,
): NativeVulnerabilityQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  const vulnerabilityId = stringValue(filter?.get('uuid')).trim();
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
    ...(vulnerabilityId === '' ? {} : {vulnerabilityId}),
  };
};

const nativeCounts = (page: NativePage, length: number): CollectionCounts =>
  new CollectionCounts({
    first: page.total > 0 ? (page.page - 1) * page.page_size + 1 : 0,
    all: page.total,
    filtered: page.total,
    length,
    rows: page.page_size,
  });

const fetchNativeJson = async <T>(
  gmp: NativeApiGmp,
  path: string,
  params: UrlParams,
): Promise<T> => {
  const response = await fetch(gmp.buildUrl(path, params), {
    credentials: 'include',
    headers: {
      Accept: 'application/json',
      ...(gmp.session.jwt ? {Authorization: `Bearer ${gmp.session.jwt}`} : {}),
    },
  });

  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }

  return (await response.json()) as T;
};

const nativeVulnerabilityToModel = (
  item: NativeVulnerabilityPayload,
): Vulnerability => {
  const solutionType = stringValue(item.solution_type);
  const solutionDescription = stringValue(item.solution);
  const maxEpss = epssFromNative(item.max_epss);
  const maxSeverity = epssFromNative(item.max_severity);
  return Vulnerability.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name),
    family: stringValue(item.family),
    results: {
      count: integerValue(item.result_count),
      oldest: stringValue(item.oldest_result),
      newest: stringValue(item.newest_result),
    },
    hosts: {count: integerValue(item.host_count)},
    severity: numberValue(item.severity),
    qod: integerValue(item.qod),
    cves: item.cves ?? [],
    certs: (item.cert_refs ?? []).map(certFromNative),
    xrefs: (item.xrefs ?? []).map(xrefFromNative),
    epss:
      maxEpss || maxSeverity
        ? {
            maxEpss,
            maxSeverity,
          }
        : undefined,
    summary: stringValue(item.summary),
    insight: stringValue(item.insight),
    affected: stringValue(item.affected),
    impact: stringValue(item.impact),
    detection: stringValue(item.detection),
    solution:
      solutionType || solutionDescription
        ? {
            type: solutionType,
            description: solutionDescription,
          }
        : undefined,
  });
};

export const fetchNativeVulnerabilities = async (
  gmp: NativeApiGmp,
  query: NativeVulnerabilityQuery,
): Promise<NativeVulnerabilitiesResponse> => {
  const payload = await fetchNativeJson<NativeVulnerabilitiesPayload>(
    gmp,
    'api/v1/vulnerabilities',
    {
      token: gmp.session.token,
      page: query.page,
      page_size: query.pageSize,
      sort: query.sort,
      filter: query.filter,
      ...(query.vulnerabilityId === undefined
        ? {}
        : {vulnerability_id: query.vulnerabilityId}),
    },
  );
  const page = {
    page: integerValue(payload.page?.page, 1),
    page_size: integerValue(payload.page?.page_size, query.pageSize),
    total: integerValue(payload.page?.total),
    sort: stringValue(payload.page?.sort),
    filter: stringValue(payload.page?.filter),
  };
  const vulnerabilities = (payload.items ?? []).map(nativeVulnerabilityToModel);
  return {
    vulnerabilities,
    counts: nativeCounts(page, vulnerabilities.length),
    page,
  };
};

export const exportNativeVulnerabilityMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativeVulnerabilityPayload>(
    gmp,
    `api/v1/vulnerabilities/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};

export const exportNativeVulnerabilitiesMetadata = async (
  gmp: NativeApiGmp,
  ids: string[],
): Promise<Response<string>> => {
  const vulnerabilities = await Promise.all(
    ids.map(async id => {
      const payload = await fetchNativeJson<NativeVulnerabilityPayload>(
        gmp,
        `api/v1/vulnerabilities/${encodeURIComponent(id)}/export`,
        {token: gmp.session.token},
      );
      return payload;
    }),
  );
  return new Response(`${JSON.stringify({vulnerabilities}, null, 2)}\n`);
};
