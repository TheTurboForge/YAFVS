/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import Response from 'gmp/http/response';
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
  created_at?: string;
  modified_at?: string;
}

interface NativeHostOperatingSystemPayload {
  id: string;
  name: string;
  comment?: string;
  operating_system_id?: string;
  operating_system_name?: string;
  title?: string;
  source_type?: string;
  source_id?: string;
  source_data?: string;
  created_at?: string;
  modified_at?: string;
}

interface NativeUserTagPayload {
  id: string;
  name: string;
  value: string;
  comment: string;
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
  user_tags?: NativeUserTagPayload[];
  created_at?: string;
  modified_at?: string;
}

interface NativeHostsPayload {
  page?: Partial<NativePage>;
  items?: NativeHostPayload[];
}

interface NativeHostDetailMetadataPayload {
  name: string;
  value: string;
}

interface NativeHostDetailPayload {
  asset: NativeHostPayload;
  identifiers?: NativeHostIdentifierPayload[];
  operating_systems?: NativeHostOperatingSystemPayload[];
  details?: NativeHostDetailMetadataPayload[];
  user_tags?: NativeUserTagPayload[];
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

export interface NativeHostResponse {
  host: Host;
}

export interface NativeHostCreateArgs {
  name: string;
  comment?: string;
}

export interface NativeHostPatchArgs {
  id: string;
  comment?: string;
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

const matchingOperatingSystem = (
  identifier: NativeHostIdentifierPayload,
  operatingSystems: NativeHostOperatingSystemPayload[] = [],
) =>
  identifier.name === 'OS'
    ? operatingSystems.find(
        os => os.operating_system_name === identifier.value,
      )
    : undefined;

const nativeIdentifierToElement = (
  item: NativeHostIdentifierPayload,
  operatingSystems?: NativeHostOperatingSystemPayload[],
) => {
  const os = matchingOperatingSystem(item, operatingSystems);
  return {
    _id: stringValue(item.id),
    name: stringValue(item.name),
    value: stringValue(item.value),
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    os: os ? {id: stringValue(os.operating_system_id)} : undefined,
    source: {
      _id: stringValue(item.source_id),
      type: stringValue(item.source_type),
      data: stringValue(item.source_data),
    },
  };
};

const nativeIdentifierKey = (item: NativeHostIdentifierPayload): string =>
  stringValue(item.id) || `${stringValue(item.name)}:${stringValue(item.value)}`;

const nativeIdentifierItems = (
  item: NativeHostPayload,
  detail?: Pick<NativeHostDetailPayload, 'identifiers'>,
): NativeHostIdentifierPayload[] => {
  const identifiers = new Map<string, NativeHostIdentifierPayload>();
  for (const identifier of item.identifiers ?? []) {
    identifiers.set(nativeIdentifierKey(identifier), identifier);
  }
  for (const identifier of detail?.identifiers ?? []) {
    identifiers.set(nativeIdentifierKey(identifier), identifier);
  }
  return Array.from(identifiers.values());
};

const nativeUserTagsElement = (tags: NativeUserTagPayload[] = []) => ({
  tag: tags.map(tag => ({
    _id: stringValue(tag.id),
    name: stringValue(tag.name),
    value: stringValue(tag.value),
    comment: stringValue(tag.comment),
  })),
});

const nativeDetailToElement = (item: NativeHostDetailMetadataPayload) => ({
  name: stringValue(item.name),
  value: stringValue(item.value),
});

const routeFromTraceroute = (detail?: NativeHostDetailPayload['details']) => {
  const traceroute = detail?.find(item => item.name === 'traceroute');
  const hosts = stringValue(traceroute?.value)
    .split(',')
    .map(value => value.trim())
    .filter(value => value.length > 0)
    .map(ip => ({ip}));
  return hosts.length > 0 ? {route: {host: hosts}} : undefined;
};

const nativeHostToModel = (
  item: NativeHostPayload,
  detail?: Pick<
    NativeHostDetailPayload,
    'details' | 'identifiers' | 'operating_systems' | 'user_tags'
  >,
): Host => {
  const details = new Map<string, {name: string; value: string}>();
  if (item.best_os_cpe) {
    details.set('best_os_cpe', {name: 'best_os_cpe', value: item.best_os_cpe});
  }
  if (item.best_os_txt) {
    details.set('best_os_txt', {name: 'best_os_txt', value: item.best_os_txt});
  }
  for (const metadata of detail?.details ?? []) {
    details.set(stringValue(metadata.name), nativeDetailToElement(metadata));
  }

  const identifiers = nativeIdentifierItems(item, detail).map(identifier =>
    nativeIdentifierToElement(identifier, detail?.operating_systems),
  );
  const route = routeFromTraceroute(detail?.details);

  return Host.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name),
    comment: stringValue(item.comment),
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    writable: detail ? 1 : undefined,
    user_tags: detail
      ? nativeUserTagsElement(detail.user_tags ?? item.user_tags ?? [])
      : undefined,
    host: {
      severity: {value: String(numberValue(item.severity))},
      detail: Array.from(details.values()),
      routes: route,
    },
    identifiers: {
      identifier: identifiers,
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
  const hosts = (payload.items ?? []).map(item => nativeHostToModel(item));
  return {
    hosts,
    counts: nativeCounts(page, hosts.length),
    page,
  };
};

export const fetchNativeHost = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<NativeHostResponse> => {
  const payload = await fetchNativeJson<NativeHostDetailPayload>(
    gmp,
    `api/v1/hosts/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return {
    host: nativeHostToModel(payload.asset, payload),
  };
};

export const exportNativeHostMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativeHostDetailPayload>(
    gmp,
    `api/v1/hosts/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};

export const exportNativeHostsMetadata = async (
  gmp: NativeApiGmp,
  ids: string[],
): Promise<Response<string>> => {
  const hosts = await Promise.all(
    ids.map(async id => {
      const payload = await fetchNativeJson<NativeHostDetailPayload>(
        gmp,
        `api/v1/hosts/${encodeURIComponent(id)}/export`,
        {token: gmp.session.token},
      );
      return payload;
    }),
  );
  return new Response(`${JSON.stringify({hosts}, null, 2)}\n`);
};

export const createNativeHost = async (
  gmp: NativeApiGmp,
  args: NativeHostCreateArgs,
): Promise<Response<Host>> => {
  const payload = await writeNativeJson<NativeHostDetailPayload>(
    gmp,
    'api/v1/hosts',
    {
      name: args.name,
      comment: args.comment ?? '',
    },
  );
  return new Response(nativeHostToModel(payload.asset, payload));
};

export const patchNativeHostComment = async (
  gmp: NativeApiGmp,
  args: NativeHostPatchArgs,
): Promise<Response<Host>> => {
  const payload = await writeNativeJson<NativeHostDetailPayload>(
    gmp,
    `api/v1/hosts/${encodeURIComponent(args.id)}`,
    {comment: args.comment ?? ''},
    'PATCH',
  );
  return new Response(nativeHostToModel(payload.asset, payload));
};
