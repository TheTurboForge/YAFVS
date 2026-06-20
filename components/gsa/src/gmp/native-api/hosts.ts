/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import type {UrlParams} from 'gmp/http/utils';
import type Filter from 'gmp/models/filter';
import Host from 'gmp/models/host';

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

interface NativeHostIdentifierPayload {
  id: string;
  name: string;
  value: string;
  source_type?: string;
  source_id?: string;
  source_data?: string;
}

interface NativeHostPayload {
  id: string;
  name: string;
  comment?: string;
  hostname?: string;
  ip?: string;
  best_os_cpe?: string;
  best_os_txt?: string;
  severity: number;
  identifiers?: NativeHostIdentifierPayload[];
  created_at?: string;
  modified_at?: string;
}

interface NativeHostsPayload {
  page?: Partial<NativePage>;
  items?: NativeHostPayload[];
}

export interface NativeHostsQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
}

export interface NativeHostsResponse {
  hosts: Host[];
  counts: CollectionCounts;
  page: NativePage;
}

const HOST_SORT_FIELDS: Record<string, string> = {
  name: 'name',
  hostname: 'hostname',
  ip: 'ip',
  os: 'os',
  severity: 'severity',
  modified: 'modified',
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
  const nativeField = HOST_SORT_FIELDS[rawField] ?? rawField;
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

export const nativeHostsQueryFromFilter = (filter?: Filter): NativeHostsQuery => {
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

const nativeIdentifierToElement = (item: NativeHostIdentifierPayload) => ({
  _id: stringValue(item.id),
  name: stringValue(item.name),
  value: stringValue(item.value),
  source: {
    _id: stringValue(item.source_id),
    type: stringValue(item.source_type),
    data: stringValue(item.source_data),
  },
});

const nativeHostToModel = (item: NativeHostPayload): Host => {
  const details: Array<{name: string; value: string}> = [];
  if (item.best_os_cpe) {
    details.push({name: 'best_os_cpe', value: item.best_os_cpe});
  }
  if (item.best_os_txt) {
    details.push({name: 'best_os_txt', value: item.best_os_txt});
  }

  return Host.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name),
    comment: stringValue(item.comment),
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    host: {
      severity: {value: String(numberValue(item.severity))},
      detail: details,
    },
    identifiers: {
      identifier: (item.identifiers ?? []).map(nativeIdentifierToElement),
    },
  });
};

export const fetchNativeHosts = async (
  gmp: NativeApiGmp,
  query: NativeHostsQuery,
): Promise<NativeHostsResponse> => {
  const payload = await fetchNativeJson<NativeHostsPayload>(
    gmp,
    'api/v1/hosts',
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
  const hosts = (payload.items ?? []).map(nativeHostToModel);
  return {
    hosts,
    counts: nativeCounts(page, hosts.length),
    page,
  };
};
