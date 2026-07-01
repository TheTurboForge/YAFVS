/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import Response from 'gmp/http/response';
import type {UrlParams} from 'gmp/http/utils';
import type Filter from 'gmp/models/filter';
import OperatingSystem from 'gmp/models/os';

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

interface NativeOperatingSystemPayload {
  id: string;
  name: string;
  title?: string;
  latest_severity?: number | null;
  highest_severity?: number | null;
  average_severity?: number | null;
  hosts: number;
  all_hosts: number;
  created_at?: string;
  modified_at?: string;
  user_tags?: NativeUserTagPayload[];
}

interface NativeUserTagPayload {
  id: string;
  name: string;
  value: string;
  comment: string;
}

interface NativeOperatingSystemsPayload {
  page?: Partial<NativePage>;
  items?: NativeOperatingSystemPayload[];
}

export interface NativeOperatingSystemQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
}

export interface NativeOperatingSystemsResponse {
  operatingSystems: OperatingSystem[];
  counts: CollectionCounts;
  page: NativePage;
}

export interface NativeOperatingSystemResponse {
  operatingSystem: OperatingSystem;
}

const OPERATING_SYSTEM_SORT_FIELDS: Record<string, string> = {
  name: 'name',
  title: 'title',
  latest_severity: 'latest_severity',
  highest_severity: 'highest_severity',
  average_severity: 'average_severity',
  hosts: 'hosts',
  all_hosts: 'all_hosts',
  modified: 'modified',
};

const stringValue = (value: unknown): string =>
  typeof value === 'string' ? value : '';

const integerValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const optionalNumberValue = (value: unknown): number | undefined => {
  if (value === null || value === undefined || value === '') {
    return undefined;
  }
  const parsed = Number.parseFloat(String(value));
  return Number.isFinite(parsed) ? parsed : undefined;
};

const nativeSortFromFilter = (filter?: Filter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending) || 'latest_severity';
  const nativeField = OPERATING_SYSTEM_SORT_FIELDS[rawField] ?? rawField;
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

export const nativeOperatingSystemsQueryFromFilter = (
  filter?: Filter,
): NativeOperatingSystemQuery => {
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

const severityValueElement = (value: unknown) => {
  const parsed = optionalNumberValue(value);
  return parsed === undefined ? undefined : {value: parsed};
};

const nativeUserTagsElement = (tags: NativeUserTagPayload[] = []) => ({
  tag: tags.map(tag => ({
    _id: stringValue(tag.id),
    name: stringValue(tag.name),
    value: stringValue(tag.value),
    comment: stringValue(tag.comment),
  })),
});

const nativeOperatingSystemToModel = (
  item: NativeOperatingSystemPayload,
  {detail = false}: {detail?: boolean} = {},
): OperatingSystem =>
  OperatingSystem.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name),
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    in_use: integerValue(item.all_hosts) > 0 ? 1 : 0,
    writable: detail ? 1 : 0,
    user_tags: detail ? nativeUserTagsElement(item.user_tags ?? []) : undefined,
    os: {
      title: stringValue(item.title),
      installs: integerValue(item.hosts),
      all_installs: integerValue(item.all_hosts),
      latest_severity: severityValueElement(item.latest_severity),
      highest_severity: severityValueElement(item.highest_severity),
      average_severity: severityValueElement(item.average_severity),
    },
  });

export const fetchNativeOperatingSystems = async (
  gmp: NativeApiGmp,
  query: NativeOperatingSystemQuery,
): Promise<NativeOperatingSystemsResponse> => {
  const payload = await fetchNativeJson<NativeOperatingSystemsPayload>(
    gmp,
    'api/v1/operating-systems',
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
  const operatingSystems = (payload.items ?? []).map(item =>
    nativeOperatingSystemToModel(item),
  );
  return {
    operatingSystems,
    counts: nativeCounts(page, operatingSystems.length),
    page,
  };
};

export const fetchNativeOperatingSystem = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<NativeOperatingSystemResponse> => {
  const payload = await fetchNativeJson<NativeOperatingSystemPayload>(
    gmp,
    `api/v1/operating-systems/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return {
    operatingSystem: nativeOperatingSystemToModel(payload, {detail: true}),
  };
};

export const exportNativeOperatingSystemMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativeOperatingSystemPayload>(
    gmp,
    `api/v1/operating-systems/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};
