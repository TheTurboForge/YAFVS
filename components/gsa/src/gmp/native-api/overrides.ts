/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import Response from 'gmp/http/response';
import type {UrlParams} from 'gmp/http/utils';
import type QueryFilter from 'gmp/models/filter';
import Override from 'gmp/models/override';

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

interface NativeReferencePayload {
  id: string;
  name: string;
}

interface NativeTaskReferencePayload extends NativeReferencePayload {
  trash?: boolean;
}

interface NativeOverrideNvtPayload extends NativeReferencePayload {
  type?: string;
}

interface NativeOverrideOwnerPayload {
  name?: string;
}

interface NativeOverridePayload {
  id: string;
  owner?: NativeOverrideOwnerPayload;
  nvt?: NativeOverrideNvtPayload;
  text?: string;
  text_excerpt?: boolean;
  hosts?: string;
  port?: string;
  severity?: number | null;
  new_severity?: number | null;
  writable?: boolean;
  in_use?: boolean;
  orphan?: boolean;
  active?: boolean;
  end_time?: string | null;
  task?: NativeTaskReferencePayload;
  result?: NativeReferencePayload;
  permissions?: string[];
  created_at?: string;
  modified_at?: string;
}

interface NativeOverridesPayload {
  page?: Partial<NativePage>;
  items?: NativeOverridePayload[];
}

export interface NativeOverridesQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
  active: string;
  text: string;
  taskName: string;
}

export interface NativeOverridesResponse {
  overrides: Override[];
  counts: CollectionCounts;
  page: NativePage;
}

const OVERRIDE_SORT_FIELDS: Record<string, string> = {
  text: 'text',
  nvt: 'nvt',
  hosts: 'hosts',
  port: 'port',
  severity: 'severity',
  newSeverity: 'newSeverity',
  new_severity: 'new_severity',
  active: 'active',
  created: 'created',
  modified: 'modified',
};

const stringValue = (value: unknown): string =>
  typeof value === 'string' ? value : '';

const integerValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const yesNoValue = (value?: boolean): 0 | 1 => (value === true ? 1 : 0);

const nativeSortFromFilter = (filter?: QueryFilter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending) || 'text';
  const nativeField = OVERRIDE_SORT_FIELDS[rawField] ?? rawField;
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

const nativeActiveFromFilter = (filter?: QueryFilter): string => {
  const value = filter?.get('active');
  if (value === 1 || value === '1') {
    return '1';
  }
  if (value === 0 || value === '0') {
    return '0';
  }
  return '';
};

export const nativeOverridesQueryFromFilter = (
  filter?: QueryFilter,
): NativeOverridesQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
    active: nativeActiveFromFilter(filter),
    text: stringValue(filter?.get('text')),
    taskName: stringValue(filter?.get('task_name')),
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

const referenceElement = (reference?: NativeReferencePayload) =>
  reference
    ? {
        _id: stringValue(reference.id),
        name: stringValue(reference.name),
      }
    : undefined;

const taskReferenceElement = (reference?: NativeTaskReferencePayload) =>
  reference
    ? {
        _id: stringValue(reference.id),
        name: stringValue(reference.name),
        trash: yesNoValue(reference.trash),
      }
    : undefined;

const nativeOverrideToModel = (item: NativeOverridePayload): Override =>
  Override.fromElement({
    _id: stringValue(item.id),
    owner: {name: stringValue(item.owner?.name)},
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    writable: yesNoValue(item.writable ?? true),
    in_use: yesNoValue(item.in_use),
    orphan: yesNoValue(item.orphan),
    active: yesNoValue(item.active ?? true),
    end_time: stringValue(item.end_time),
    permissions: {
      permission: (item.permissions ?? ['get_overrides']).map(name => ({name})),
    },
    nvt: {
      _oid: stringValue(item.nvt?.id),
      name: stringValue(item.nvt?.name),
    },
    text: {
      __text: stringValue(item.text),
      _excerpt: yesNoValue(item.text_excerpt),
    },
    text_excerpt: yesNoValue(item.text_excerpt),
    hosts: stringValue(item.hosts),
    port: stringValue(item.port),
    severity: item.severity ?? undefined,
    new_severity: item.new_severity ?? undefined,
    task: taskReferenceElement(item.task),
    result: referenceElement(item.result),
  });

const normalizePage = (
  payloadPage: Partial<NativePage> | undefined,
  query: NativeOverridesQuery,
): NativePage => ({
  page: payloadPage?.page ?? query.page,
  page_size: payloadPage?.page_size ?? query.pageSize,
  total: payloadPage?.total ?? 0,
  sort: payloadPage?.sort ?? query.sort,
  filter: payloadPage?.filter ?? query.filter,
});

export const fetchNativeOverrides = async (
  gmp: NativeApiGmp,
  query: NativeOverridesQuery,
): Promise<NativeOverridesResponse> => {
  const payload = await fetchNativeJson<NativeOverridesPayload>(
    gmp,
    'api/v1/overrides',
    {
      token: gmp.session.token,
      page: query.page,
      page_size: query.pageSize,
      sort: query.sort,
      filter: query.filter,
      active: query.active,
      text: query.text,
      task_name: query.taskName,
    },
  );
  const page = normalizePage(payload.page, query);
  const overrides = (payload.items ?? []).map(nativeOverrideToModel);
  return {
    overrides,
    counts: nativeCounts(page, overrides.length),
    page,
  };
};

export const fetchNativeOverride = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Override> => {
  const payload = await fetchNativeJson<NativeOverridePayload>(
    gmp,
    `api/v1/overrides/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return nativeOverrideToModel(payload);
};

export const exportNativeOverrideMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativeOverridePayload>(
    gmp,
    `api/v1/overrides/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};
