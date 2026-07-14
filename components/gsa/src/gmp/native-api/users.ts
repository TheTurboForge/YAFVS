/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import Response from 'gmp/http/response';
import type {UrlParams} from 'gmp/http/utils';
import date from 'gmp/models/date';
import type QueryFilter from 'gmp/models/filter';
import User from 'gmp/models/user';

interface NativeApiSession {
  readonly jwt?: string;
  readonly token?: string;
}

interface NativeApiGmp {
  readonly session: NativeApiSession;
  buildUrl(path: string, params?: UrlParams): string;
}

interface NativeUserMetadataPayload {
  id: string;
  name: string;
  comment?: string;
}

interface NativeUserManagementPayload extends NativeUserMetadataPayload {
  auth_method: 'password' | 'ldap' | 'radius';
  created_at?: string;
  modified_at?: string;
}

interface NativePage {
  page: number;
  page_size: number;
  total: number;
  sort: string;
  filter: string;
}

interface NativeUserManagementCollectionPayload {
  page?: Partial<NativePage>;
  items?: NativeUserManagementPayload[];
}

export interface NativeUserManagementQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
}

export interface NativeUserManagementResponse {
  users: User[];
  counts: CollectionCounts;
  page: NativePage;
}

export interface NativeUserCreateArgs {
  authMethod: 'password' | 'ldap' | 'radius';
  comment: string;
  name: string;
  password?: string;
}

export interface NativeUserPatchArgs extends NativeUserCreateArgs {
  id: string;
}

const stringValue = (value: unknown): string =>
  typeof value === 'string' ? value : '';

const integerValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const USER_SORT_FIELDS: Record<string, string> = {
  name: 'name',
  created: 'created',
  creation_time: 'created',
  modified: 'modified',
  modification_time: 'modified',
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

const nativeUserManagementToModel = (item: NativeUserManagementPayload): User =>
  new User({
    id: stringValue(item.id),
    name: stringValue(item.name),
    comment: stringValue(item.comment),
    authMethod: item.auth_method,
    creationTime:
      typeof item.created_at === 'string' && item.created_at !== ''
        ? date(item.created_at)
        : undefined,
    modificationTime:
      typeof item.modified_at === 'string' && item.modified_at !== ''
        ? date(item.modified_at)
        : undefined,
  });

const userManagementHeaders = (gmp: NativeApiGmp, withJsonBody = false) => ({
  Accept: 'application/json',
  ...(withJsonBody ? {'Content-Type': 'application/json'} : {}),
  ...(gmp.session.token ? {'X-TurboVAS-Token': gmp.session.token} : {}),
  ...(gmp.session.jwt ? {Authorization: `Bearer ${gmp.session.jwt}`} : {}),
});

const fetchUserManagementJson = async <T>(
  gmp: NativeApiGmp,
  path: string,
  params?: UrlParams,
): Promise<T> => {
  const response = await fetch(
    gmp.buildUrl(path, {token: gmp.session.token, ...params}),
    {
      credentials: 'include',
      headers: userManagementHeaders(gmp),
    },
  );
  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }
  return (await response.json()) as T;
};

const writeUserManagementJson = async <T>(
  gmp: NativeApiGmp,
  path: string,
  body: unknown,
  method: 'POST' | 'PATCH',
): Promise<T> => {
  const response = await fetch(gmp.buildUrl(path), {
    method,
    credentials: 'include',
    headers: userManagementHeaders(gmp, true),
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }
  return (await response.json()) as T;
};

export const nativeUserManagementQueryFromFilter = (
  filter: QueryFilter,
): NativeUserManagementQuery => {
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

export const fetchUserManagementUsers = async (
  gmp: NativeApiGmp,
  query: NativeUserManagementQuery,
): Promise<NativeUserManagementResponse> => {
  const payload =
    await fetchUserManagementJson<NativeUserManagementCollectionPayload>(
      gmp,
      'api/v1/user-management/users',
      {
        page: query.page,
        page_size: query.pageSize,
        sort: query.sort,
        filter: query.filter,
      },
    );
  const page = {
    page: integerValue(payload.page?.page, query.page),
    page_size: integerValue(payload.page?.page_size, query.pageSize),
    total: integerValue(payload.page?.total),
    sort: stringValue(payload.page?.sort || query.sort),
    filter: stringValue(payload.page?.filter || query.filter),
  };
  const users = (payload.items ?? []).map(nativeUserManagementToModel);
  return {users, counts: nativeCounts(page, users.length), page};
};

export const fetchUserManagementUser = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<User> => {
  const payload = await fetchUserManagementJson<NativeUserManagementPayload>(
    gmp,
    `api/v1/user-management/users/${encodeURIComponent(id)}`,
  );
  return nativeUserManagementToModel(payload);
};

export const createNativeUser = async (
  gmp: NativeApiGmp,
  {authMethod, comment, name, password}: NativeUserCreateArgs,
): Promise<Response<{id: string}>> => {
  const payload = await writeUserManagementJson<NativeUserManagementPayload>(
    gmp,
    'api/v1/user-management/users',
    {
      name,
      comment,
      auth_method: authMethod,
      ...(password === undefined ? {} : {password}),
    },
    'POST',
  );
  return new Response({id: stringValue(payload.id)});
};

export const patchNativeUser = async (
  gmp: NativeApiGmp,
  {id, authMethod, comment, name, password}: NativeUserPatchArgs,
): Promise<Response<{id: string}>> => {
  const payload = await writeUserManagementJson<NativeUserManagementPayload>(
    gmp,
    `api/v1/user-management/users/${encodeURIComponent(id)}`,
    {
      name,
      comment,
      auth_method: authMethod,
      ...(password === undefined ? {} : {password}),
    },
    'PATCH',
  );
  return new Response({id: stringValue(payload.id)});
};

export const deleteNativeUser = async (
  gmp: NativeApiGmp,
  id: string,
  inheritorId?: string,
): Promise<void> => {
  const response = await fetch(
    gmp.buildUrl(
      `api/v1/user-management/users/${encodeURIComponent(id)}`,
      inheritorId === undefined ? undefined : {inheritor_id: inheritorId},
    ),
    {
      method: 'DELETE',
      credentials: 'include',
      headers: userManagementHeaders(gmp),
    },
  );
  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }
};

export const exportNativeUserMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativeUserMetadataPayload>(
    gmp,
    `api/v1/users/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};

export const exportNativeUsersMetadata = async (
  gmp: NativeApiGmp,
  ids: string[],
): Promise<Response<string>> => {
  const users = await Promise.all(
    ids.map(async id => {
      const payload = await fetchNativeJson<NativeUserMetadataPayload>(
        gmp,
        `api/v1/users/${encodeURIComponent(id)}`,
        {token: gmp.session.token},
      );
      return payload;
    }),
  );
  return new Response(`${JSON.stringify({users}, null, 2)}\n`);
};
