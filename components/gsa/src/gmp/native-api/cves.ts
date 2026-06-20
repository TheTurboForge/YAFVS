/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import type {UrlParams} from 'gmp/http/utils';
import type Filter from 'gmp/models/filter';
import Cve from 'gmp/models/cve';

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

interface NativeCatalogEpssPayload {
  score?: number;
  percentile?: number;
}

interface NativeCatalogCvePayload {
  id: string;
  name?: string;
  comment?: string;
  description?: string;
  cvss_base_vector?: string;
  severity?: number;
  products?: string[];
  epss?: NativeCatalogEpssPayload;
  published_at?: string;
  modified_at?: string;
}

interface NativeCvesPayload {
  page?: Partial<NativePage>;
  items?: NativeCatalogCvePayload[];
}

export interface NativeCvesQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
}

export interface NativeCvesResponse {
  cves: Cve[];
  counts: CollectionCounts;
  page: NativePage;
}

const CVE_SORT_FIELDS: Record<string, string> = {
  name: 'name',
  description: 'description',
  published: 'published',
  cvssBaseVector: 'cvssBaseVector',
  severity: 'severity',
  epss_score: 'epss_score',
  epss_percentile: 'epss_percentile',
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
  const nativeField = CVE_SORT_FIELDS[rawField] ?? rawField;
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

export const nativeCvesQueryFromFilter = (filter?: Filter): NativeCvesQuery => {
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

const nativeCveToModel = (item: NativeCatalogCvePayload): Cve =>
  Cve.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name || item.id),
    comment: stringValue(item.comment),
    creation_time: stringValue(item.published_at),
    modification_time: stringValue(item.modified_at),
    update_time: stringValue(item.modified_at),
    cve: {
      description: stringValue(item.description),
      cvss_vector: stringValue(item.cvss_base_vector),
      severity: numberValue(item.severity),
      products: (item.products ?? []).join(' '),
      epss: item.epss
        ? {
            score: numberValue(item.epss.score),
            percentile: numberValue(item.epss.percentile),
          }
        : undefined,
    },
  });

export const fetchNativeCves = async (
  gmp: NativeApiGmp,
  query: NativeCvesQuery,
): Promise<NativeCvesResponse> => {
  const payload = await fetchNativeJson<NativeCvesPayload>(
    gmp,
    'api/v1/cves',
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
  const cves = (payload.items ?? []).map(nativeCveToModel);
  return {
    cves,
    counts: nativeCounts(page, cves.length),
    page,
  };
};

export const fetchNativeCve = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Cve> => {
  const payload = await fetchNativeJson<NativeCatalogCvePayload>(
    gmp,
    `api/v1/cves/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return nativeCveToModel(payload);
};
