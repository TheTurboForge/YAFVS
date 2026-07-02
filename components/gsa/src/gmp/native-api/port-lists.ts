/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import Response from 'gmp/http/response';
import type {UrlParams} from 'gmp/http/utils';
import {NO_VALUE, YES_VALUE} from 'gmp/parser';
import PortList from 'gmp/models/port-list';
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

interface NativePortCountPayload {
  all?: number;
  tcp?: number;
  udp?: number;
}

interface NativePortRangePayload {
  id: string;
  protocol: string;
  start: number;
  end: number;
  comment?: string;
}

interface NativePortListTargetPayload {
  id: string;
  name: string;
}

interface NativeUserTagPayload {
  id: string;
  name: string;
  value: string;
  comment: string;
}

interface NativePortListPayload {
  id: string;
  name: string;
  comment?: string;
  port_count?: NativePortCountPayload;
  port_ranges?: NativePortRangePayload[];
  targets?: NativePortListTargetPayload[];
  user_tags?: NativeUserTagPayload[];
  predefined?: boolean;
  deprecated?: boolean;
  created_at?: string;
  modified_at?: string;
}

interface NativePortListsPayload {
  page?: Partial<NativePage>;
  items?: NativePortListPayload[];
}

export interface NativePortListsQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
}

export interface NativePortListsResponse {
  portLists: PortList[];
  counts: CollectionCounts;
  page: NativePage;
}

const PORT_LIST_SORT_FIELDS: Record<string, string> = {
  name: 'name',
  total: 'total',
  tcp: 'tcp',
  udp: 'udp',
  predefined: 'predefined',
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
  const nativeField = PORT_LIST_SORT_FIELDS[rawField] ?? rawField;
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

export const nativePortListsQueryFromFilter = (
  filter?: QueryFilter,
): NativePortListsQuery => {
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

const nativeUserTagsElement = (tags: NativeUserTagPayload[] = []) => ({
  tag: tags.map(tag => ({
    _id: stringValue(tag.id),
    name: stringValue(tag.name),
    value: stringValue(tag.value),
    comment: stringValue(tag.comment),
  })),
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
  const response = await fetch(gmp.buildUrl(path), {
    method: 'POST',
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

const nativePortListToModel = (
  item: NativePortListPayload,
  {detail = false}: {detail?: boolean} = {},
): PortList =>
  PortList.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name),
    comment: stringValue(item.comment),
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    predefined: item.predefined ? YES_VALUE : NO_VALUE,
    deprecated: item.deprecated ? YES_VALUE : NO_VALUE,
    writable: 1,
    port_count: {
      all: String(integerValue(item.port_count?.all)),
      tcp: String(integerValue(item.port_count?.tcp)),
      udp: String(integerValue(item.port_count?.udp)),
    },
    port_ranges: {
      port_range: (item.port_ranges ?? []).map(range => ({
        _id: stringValue(range.id),
        type: range.protocol === 'udp' ? 'udp' : 'tcp',
        start: integerValue(range.start),
        end: integerValue(range.end),
        comment: stringValue(range.comment),
      })),
    },
    targets: {
      target: (item.targets ?? []).map(target => ({
        _id: stringValue(target.id),
        name: stringValue(target.name),
      })),
    },
    user_tags: detail ? nativeUserTagsElement(item.user_tags ?? []) : undefined,
  });

export const fetchNativePortLists = async (
  gmp: NativeApiGmp,
  query: NativePortListsQuery,
): Promise<NativePortListsResponse> => {
  const payload = await fetchNativeJson<NativePortListsPayload>(
    gmp,
    'api/v1/port-lists',
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
  const portLists = (payload.items ?? []).map(item => nativePortListToModel(item));
  return {
    portLists,
    counts: nativeCounts(page, portLists.length),
    page,
  };
};

export const fetchNativePortList = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<PortList> => {
  const payload = await fetchNativeJson<NativePortListPayload>(
    gmp,
    `api/v1/port-lists/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return nativePortListToModel(payload, {detail: true});
};

export const exportNativePortListMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativePortListPayload>(
    gmp,
    `api/v1/port-lists/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};

export const cloneNativePortList = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<{id: string}>> => {
  const payload = await writeNativeJson<NativePortListPayload>(
    gmp,
    `api/v1/port-lists/${encodeURIComponent(id)}/clone`,
    {},
  );
  return new Response({id: stringValue(payload.id)});
};
