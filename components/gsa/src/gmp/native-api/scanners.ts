/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import Response from 'gmp/http/response';
import type {UrlParams} from 'gmp/http/utils';
import ActionResult from 'gmp/models/action-result';
import type Filter from 'gmp/models/filter';
import Scanner from 'gmp/models/scanner';

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

interface NativeScannerCredentialPayload {
  id: string;
  name: string;
}

interface NativeScannerTaskPayload {
  id: string;
  name: string;
  usage_type?: string;
}

interface NativeUserTagPayload {
  id: string;
  name: string;
  value: string;
  comment: string;
}

interface NativeScannerPayload {
  id: string;
  name: string;
  comment?: string;
  host?: string;
  port?: number;
  scanner_type?: number;
  credential?: NativeScannerCredentialPayload;
  relay_host?: string;
  relay_port?: number;
  tasks?: NativeScannerTaskPayload[];
  user_tags?: NativeUserTagPayload[];
  created_at?: string;
  modified_at?: string;
}

interface NativeScannersPayload {
  page?: Partial<NativePage>;
  items?: NativeScannerPayload[];
}

interface NativeScannerPatchArgs {
  id: string;
  name?: string;
  comment?: string;
}

export interface NativeScannersQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
}

export interface NativeScannersResponse {
  scanners: Scanner[];
  counts: CollectionCounts;
  page: NativePage;
}

export interface NativeScannerResponse {
  scanner: Scanner;
}

const SCANNER_SORT_FIELDS: Record<string, string> = {
  name: 'name',
  host: 'host',
  port: 'port',
  type: 'type',
  credential: 'credential',
  modified: 'modified',
};

const stringValue = (value: unknown): string =>
  typeof value === 'string' ? value : '';

const integerValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const nativeSortFromFilter = (filter?: Filter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending) || 'name';
  const nativeField = SCANNER_SORT_FIELDS[rawField] ?? rawField;
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

export const nativeScannersQueryFromFilter = (
  filter?: Filter,
): NativeScannersQuery => {
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
      'X-TurboVAS-Token': gmp.session.token ?? '',
      ...(gmp.session.jwt ? {Authorization: `Bearer ${gmp.session.jwt}`} : {}),
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }

  return (await response.json()) as T;
};

const nativeUserTagsElement = (tags: NativeUserTagPayload[] = []) => ({
  tag: tags.map(tag => ({
    _id: stringValue(tag.id),
    name: stringValue(tag.name),
    value: stringValue(tag.value),
    comment: stringValue(tag.comment),
  })),
});

const nativeTaskToElement = (task: NativeScannerTaskPayload) => ({
  _id: stringValue(task.id),
  name: stringValue(task.name),
  usage_type: 'scan' as const,
});

const nativeScannerToModel = (
  item: NativeScannerPayload,
  {detail = false}: {detail?: boolean} = {},
): Scanner =>
  Scanner.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name),
    comment: stringValue(item.comment),
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    host: stringValue(item.host),
    port: integerValue(item.port),
    type: String(integerValue(item.scanner_type)),
    credential: item.credential
      ? {
          _id: stringValue(item.credential.id),
          name: stringValue(item.credential.name),
        }
      : undefined,
    relay_host: stringValue(item.relay_host),
    relay_port: integerValue(item.relay_port),
    tasks: detail
      ? {task: (item.tasks ?? []).map(nativeTaskToElement)}
      : undefined,
    user_tags: detail ? nativeUserTagsElement(item.user_tags ?? []) : undefined,
  });

export const fetchNativeScanners = async (
  gmp: NativeApiGmp,
  query: NativeScannersQuery,
): Promise<NativeScannersResponse> => {
  const payload = await fetchNativeJson<NativeScannersPayload>(
    gmp,
    'api/v1/scanners',
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
  const scanners = (payload.items ?? []).map(item => nativeScannerToModel(item));
  return {
    scanners,
    counts: nativeCounts(page, scanners.length),
    page,
  };
};

export const fetchNativeScanner = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<NativeScannerResponse> => {
  const payload = await fetchNativeJson<NativeScannerPayload>(
    gmp,
    `api/v1/scanners/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return {
    scanner: nativeScannerToModel(payload, {detail: true}),
  };
};

export const exportNativeScannerMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativeScannerPayload>(
    gmp,
    `api/v1/scanners/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};

export const exportNativeScannersMetadata = async (
  gmp: NativeApiGmp,
  ids: string[],
): Promise<Response<string>> => {
  const scanners = await Promise.all(
    ids.map(async id => {
      const payload = await fetchNativeJson<NativeScannerPayload>(
        gmp,
        `api/v1/scanners/${encodeURIComponent(id)}/export`,
        {token: gmp.session.token},
      );
      return payload;
    }),
  );
  return new Response(`${JSON.stringify({scanners}, null, 2)}\n`);
};

export const patchNativeScanner = async (
  gmp: NativeApiGmp,
  {id, name, comment}: NativeScannerPatchArgs,
): Promise<Response<ActionResult>> => {
  const body = {
    ...(name !== undefined ? {name} : {}),
    ...(comment !== undefined ? {comment} : {}),
  };
  const payload = await writeNativeJson<NativeScannerPayload>(
    gmp,
    `api/v1/scanners/${encodeURIComponent(id)}`,
    body,
    'PATCH',
  );
  return new Response(
    new ActionResult({
      action_result: {
        action: 'save_scanner',
        id: stringValue(payload.id),
        message: 'OK',
      },
    }),
  );
};
