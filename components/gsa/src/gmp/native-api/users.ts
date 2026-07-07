/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import type {UrlParams} from 'gmp/http/utils';
import User from 'gmp/models/user';
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

interface NativeUserPayload {
  id: string;
  name: string;
  comment?: string;
  created_at?: string;
  modified_at?: string;
}

interface NativeUsersPayload {
  page?: Partial<NativePage>;
  items?: NativeUserPayload[];
}

export interface NativeUsersQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
}

export interface NativeUsersResponse {
  users: User[];
  counts: CollectionCounts;
  page: NativePage;
}

const USER_SORT_FIELDS: Record<string, string> = {
  name: 'name',
  created: 'created',
  creation_time: 'created',
  modified: 'modified',
  modification_time: 'modified',
};

const stringValue = (value: unknown): string =>
  typeof value === 'string' ? value : '';

const integerValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const nativeMappedSortFromFilter = (
  filter: QueryFilter,
  fields: Record<string, string>,
  fallback: string,
): string => {
  const reverse = filter.get('sort-reverse');
  const ascending = filter.get('sort');
  const rawField = stringValue(reverse ?? ascending) || fallback;
  const nativeField = fields[rawField] ?? fallback;
  return reverse === undefined ? nativeField : `-${nativeField}`;
};

const nativeCounts = (page: NativePage, length: number): CollectionCounts =>
  new CollectionCounts({
    all: page.total,
    filtered: page.total,
    first: (Math.max(page.page, 1) - 1) * page.page_size + 1,
    length,
    rows: page.page_size,
  });

const fetchNativeJson = async <T>(
  gmp: NativeApiGmp,
  path: string,
  params?: UrlParams,
): Promise<T> => {
  const url = gmp.buildUrl(path, params);
  const response = await fetch(url, {
    credentials: 'include',
    headers: {
      Accept: 'application/json',
      ...(gmp.session.jwt === undefined
        ? {}
        : {Authorization: `Bearer ${gmp.session.jwt}`}),
    },
  });
  if (!response.ok) {
    throw new Error(`Native API request failed: ${response.status}`);
  }
  return (await response.json()) as T;
};

export const nativeUsersQueryFromFilter = (
  filter: QueryFilter,
): NativeUsersQuery => {
  const first = integerValue(filter.get('first'), 1);
  const rows = integerValue(filter.get('rows'), 25);
  const pageSize = rows < 1 ? 25 : rows;
  return {
    page: Math.max(1, Math.floor((Math.max(first, 1) - 1) / pageSize) + 1),
    pageSize,
    sort: nativeMappedSortFromFilter(filter, USER_SORT_FIELDS, 'name'),
    filter: stringValue(filter.get('search')),
  };
};

const nativeUserToModel = (item: NativeUserPayload): User =>
  User.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name),
    comment: stringValue(item.comment),
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
  });

export const fetchNativeUsers = async (
  gmp: NativeApiGmp,
  query: NativeUsersQuery,
): Promise<NativeUsersResponse> => {
  const payload = await fetchNativeJson<NativeUsersPayload>(gmp, 'api/v1/users', {
    token: gmp.session.token,
    page: query.page,
    page_size: query.pageSize,
    sort: query.sort,
    filter: query.filter,
  });
  const page = {
    page: integerValue(payload.page?.page, query.page),
    page_size: integerValue(payload.page?.page_size, query.pageSize),
    total: integerValue(payload.page?.total),
    sort: stringValue(payload.page?.sort || query.sort),
    filter: stringValue(payload.page?.filter || query.filter),
  };
  const users = (payload.items ?? []).map(item => nativeUserToModel(item));
  return {
    users,
    counts: nativeCounts(page, users.length),
    page,
  };
};

export const fetchNativeUser = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<User> => {
  const payload = await fetchNativeJson<NativeUserPayload>(
    gmp,
    `api/v1/users/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return nativeUserToModel(payload);
};
