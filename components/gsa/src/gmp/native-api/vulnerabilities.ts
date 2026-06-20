/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
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
  oldest_result?: string;
  newest_result?: string;
  severity: number;
  qod: number;
  result_count: number;
  host_count: number;
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
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
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
): Vulnerability =>
  Vulnerability.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name),
    results: {
      count: integerValue(item.result_count),
      oldest: stringValue(item.oldest_result),
      newest: stringValue(item.newest_result),
    },
    hosts: {count: integerValue(item.host_count)},
    severity: numberValue(item.severity),
    qod: integerValue(item.qod),
  });

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
