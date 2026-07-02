/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import Response from 'gmp/http/response';
import type {UrlParams} from 'gmp/http/utils';
import Filter from 'gmp/models/filter';
import type QueryFilter from 'gmp/models/filter';

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

interface NativeFilterAlertPayload {
  id: string;
  name: string;
}

interface NativeFilterPayload {
  id: string;
  name: string;
  comment?: string;
  filter_type?: string;
  term?: string;
  alert_count?: number;
  alerts?: NativeFilterAlertPayload[];
  created_at?: string;
  modified_at?: string;
}

interface NativeFiltersPayload {
  page?: Partial<NativePage>;
  items?: NativeFilterPayload[];
}

export interface NativeFiltersQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
  filterType?: string;
}

export interface NativeFiltersResponse {
  filters: Filter[];
  counts: CollectionCounts;
  page: NativePage;
}

export interface NativeFilterCreateArgs {
  name: string;
  comment?: string;
  filterType: string;
  term: string;
}

const FILTER_SORT_FIELDS: Record<string, string> = {
  name: 'name',
  term: 'term',
  type: 'type',
  filter_type: 'filter_type',
  modified: 'modified',
};

const stringValue = (value: unknown): string =>
  typeof value === 'string' ? value : '';

const integerValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const nativeSortFromFilter = (filter?: QueryFilter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending) || 'name';
  const nativeField = FILTER_SORT_FIELDS[rawField] ?? rawField;
  return reverse !== undefined ? `-${nativeField}` : nativeField;
};

const nativeSearchFromFilter = (filter?: QueryFilter): string => {
  const search = filter?.get('search');
  if (search !== undefined) {
    return String(search);
  }
  const criteria = filter?.toFilterCriteriaString().trim() ?? '';
  return /[=<>:~]/.test(criteria) ? '' : criteria;
};

export const nativeFiltersQueryFromFilter = (
  filter?: QueryFilter,
): NativeFiltersQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  const filterType = stringValue(
    filter?.get('type') ?? filter?.get('filter_type'),
  );
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
    ...(filterType !== '' ? {filterType} : {}),
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

const writeNativeJson = async <T>(
  gmp: NativeApiGmp,
  path: string,
  body: unknown,
): Promise<T> => {
  const response = await fetch(gmp.buildUrl(path, {token: gmp.session.token}), {
    method: 'POST',
    credentials: 'include',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...(gmp.session.jwt ? {Authorization: `Bearer ${gmp.session.jwt}`} : {}),
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }

  return (await response.json()) as T;
};

const nativeFilterToModel = (item: NativeFilterPayload): Filter =>
  Filter.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name),
    comment: stringValue(item.comment),
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    type: stringValue(item.filter_type),
    term: stringValue(item.term),
    in_use: integerValue(item.alert_count) > 0 ? 1 : 0,
    writable: 1,
    alerts: {
      alert: (item.alerts ?? []).map(alert => ({
        _id: stringValue(alert.id),
        name: stringValue(alert.name),
      })),
    },
  });

export const fetchNativeFilters = async (
  gmp: NativeApiGmp,
  query: NativeFiltersQuery,
): Promise<NativeFiltersResponse> => {
  const payload = await fetchNativeJson<NativeFiltersPayload>(
    gmp,
    'api/v1/filters',
    {
      token: gmp.session.token,
      page: query.page,
      page_size: query.pageSize,
      sort: query.sort,
      filter: query.filter,
      ...(query.filterType ? {filter_type: query.filterType} : {}),
    },
  );
  const page = {
    page: integerValue(payload.page?.page, 1),
    page_size: integerValue(payload.page?.page_size, query.pageSize),
    total: integerValue(payload.page?.total),
    sort: stringValue(payload.page?.sort),
    filter: stringValue(payload.page?.filter),
  };
  const filters = (payload.items ?? []).map(nativeFilterToModel);
  return {
    filters,
    counts: nativeCounts(page, filters.length),
    page,
  };
};

export const fetchNativeFilter = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Filter> => {
  const payload = await fetchNativeJson<NativeFilterPayload>(
    gmp,
    `api/v1/filters/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return nativeFilterToModel(payload);
};

export const exportNativeFilterMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativeFilterPayload>(
    gmp,
    `api/v1/filters/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};

export const createNativeFilter = async (
  gmp: NativeApiGmp,
  {name, comment = '', filterType, term}: NativeFilterCreateArgs,
): Promise<Response<{id: string}>> => {
  const payload = await writeNativeJson<NativeFilterPayload>(
    gmp,
    'api/v1/filters',
    {
      name,
      comment,
      filter_type: filterType,
      term,
    },
  );
  return new Response({id: stringValue(payload.id)});
};

export const cloneNativeFilter = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<{id: string}>> => {
  const payload = await writeNativeJson<NativeFilterPayload>(
    gmp,
    `api/v1/filters/${encodeURIComponent(id)}/clone`,
    {},
  );
  return new Response({id: stringValue(payload.id)});
};
