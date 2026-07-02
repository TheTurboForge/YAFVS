/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import Response from 'gmp/http/response';
import type {UrlParams} from 'gmp/http/utils';
import type QueryFilter from 'gmp/models/filter';
import ScanConfig from 'gmp/models/scan-config';
import {NO_VALUE, YES_VALUE, type YesNo} from 'gmp/parser';

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

interface NativeTrendCountPayload {
  total?: number;
  trend?: number;
}

interface NativeScanConfigTaskPayload {
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

interface NativeScanConfigPayload {
  id: string;
  name?: string;
  comment?: string;
  owner?: {name?: string};
  family_count?: number;
  families_growing?: number;
  nvt_count?: number;
  nvts_growing?: number;
  families?: NativeTrendCountPayload;
  nvts?: NativeTrendCountPayload;
  predefined?: boolean;
  deprecated?: boolean;
  writable?: boolean;
  in_use?: boolean;
  orphan?: boolean;
  trash?: boolean;
  usage_type?: string;
  tasks?: NativeScanConfigTaskPayload[];
  user_tags?: NativeUserTagPayload[];
  created_at?: string;
  modified_at?: string;
}

interface NativeScanConfigFamilyPayload {
  name?: string;
  nvt_count?: number;
  max_nvt_count?: number;
  growing?: number;
}

interface NativeScanConfigFamiliesPayload {
  scan_config_id: string;
  family_count?: number;
  families_growing?: number;
  families?: NativeScanConfigFamilyPayload[];
}

interface NativeScanConfigsPayload {
  page?: Partial<NativePage>;
  items?: NativeScanConfigPayload[];
}

export interface NativeScanConfigsQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
  predefined: string;
}

export interface NativeScanConfigsResponse {
  scanConfigs: ScanConfig[];
  counts: CollectionCounts;
  page: NativePage;
}

export interface NativeScanConfigResponse {
  scanConfig: ScanConfig;
}

export interface NativeScanConfigFamiliesResponse {
  scanConfig: ScanConfig;
}

export interface NativeScanConfigPatchRequest {
  name?: string;
  comment?: string;
}

const SCAN_CONFIG_SORT_FIELDS: Record<string, string> = {
  name: 'name',
  families_total: 'families_total',
  family_count: 'family_count',
  families_trend: 'families_trend',
  nvts_total: 'nvts_total',
  nvt_count: 'nvt_count',
  nvts_trend: 'nvts_trend',
  predefined: 'predefined',
  created: 'created',
  modified: 'modified',
};

const INHERITED_SCAN_CONFIG_ACTION_CAPABILITIES = [
  'get_configs',
  'modify_config',
  'delete_config',
  'create_config',
];

const stringValue = (value: unknown, fallback = ''): string =>
  typeof value === 'string' ? value : fallback;

const integerValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const yesNoValue = (value?: boolean): 0 | 1 => (value === true ? 1 : 0);

const trendValue = (value: number): YesNo =>
  value === 1 ? YES_VALUE : NO_VALUE;

const nativeSortFromFilter = (filter?: QueryFilter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending, 'name');
  const nativeField = SCAN_CONFIG_SORT_FIELDS[rawField] ?? rawField;
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

const nativePredefinedFromFilter = (filter?: QueryFilter): string => {
  const value = filter?.get('predefined');
  if (value === 1 || value === '1') {
    return '1';
  }
  if (value === 0 || value === '0') {
    return '0';
  }
  return '';
};

export const nativeScanConfigsQueryFromFilter = (
  filter?: QueryFilter,
): NativeScanConfigsQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
    predefined: nativePredefinedFromFilter(filter),
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

const nativeTaskToElement = (task: NativeScanConfigTaskPayload) => ({
  _id: stringValue(task.id),
  name: stringValue(task.name),
  usage_type: 'scan' as const,
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

const nativeScanConfigToModel = (
  item: NativeScanConfigPayload,
  {detail = false}: {detail?: boolean} = {},
): ScanConfig => {
  const familyCount = item.family_count ?? item.families?.total ?? 0;
  const familiesGrowing = item.families_growing ?? item.families?.trend ?? 0;
  const nvtCount = item.nvt_count ?? item.nvts?.total ?? 0;
  const nvtsGrowing = item.nvts_growing ?? item.nvts?.trend ?? 0;

  return ScanConfig.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name),
    comment: stringValue(item.comment),
    owner: {name: stringValue(item.owner?.name)},
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    writable: yesNoValue(item.writable ?? !item.predefined),
    in_use: yesNoValue(item.in_use),
    orphan: yesNoValue(item.orphan),
    trash: yesNoValue(item.trash),
    predefined: yesNoValue(item.predefined),
    deprecated: yesNoValue(item.deprecated),
    permissions: {
      // The native API contract is read-only metadata. Row action capability
      // names are synthesized locally because the actions still use inherited
      // GMP commands and global operator capabilities.
      permission: INHERITED_SCAN_CONFIG_ACTION_CAPABILITIES.map(name => ({
        name,
      })),
    },
    family_count: {
      __text: String(familyCount),
      growing: trendValue(familiesGrowing),
    },
    nvt_count: {__text: String(nvtCount), growing: trendValue(nvtsGrowing)},
    tasks: detail
      ? {task: (item.tasks ?? []).map(nativeTaskToElement)}
      : undefined,
    user_tags: detail ? nativeUserTagsElement(item.user_tags ?? []) : undefined,
  });
};

const nativeScanConfigFamiliesToModel = (
  item: NativeScanConfigFamiliesPayload,
): ScanConfig => {
  const families = item.families ?? [];
  return ScanConfig.fromElement({
    _id: stringValue(item.scan_config_id),
    family_count: {
      __text: String(item.family_count ?? families.length),
      growing: trendValue(item.families_growing ?? 0),
    },
    families: {
      family: families.map(family => ({
        name: stringValue(family.name),
        nvt_count: String(family.nvt_count ?? 0),
        max_nvt_count: String(family.max_nvt_count ?? 0),
        growing: trendValue(family.growing ?? 0),
      })),
    },
  });
};

const normalizePage = (
  payloadPage: Partial<NativePage> | undefined,
  query: NativeScanConfigsQuery,
): NativePage => ({
  page: payloadPage?.page ?? query.page,
  page_size: payloadPage?.page_size ?? query.pageSize,
  total: payloadPage?.total ?? 0,
  sort: payloadPage?.sort ?? query.sort,
  filter: payloadPage?.filter ?? query.filter,
});

export const fetchNativeScanConfigs = async (
  gmp: NativeApiGmp,
  query: NativeScanConfigsQuery,
): Promise<NativeScanConfigsResponse> => {
  const payload = await fetchNativeJson<NativeScanConfigsPayload>(
    gmp,
    'api/v1/scan-configs',
    {
      token: gmp.session.token,
      page: query.page,
      page_size: query.pageSize,
      sort: query.sort,
      filter: query.filter,
      predefined: query.predefined,
    },
  );
  const page = normalizePage(payload.page, query);
  const scanConfigs = (payload.items ?? []).map(item =>
    nativeScanConfigToModel(item),
  );
  return {
    scanConfigs,
    counts: nativeCounts(page, scanConfigs.length),
    page,
  };
};

export const fetchNativeScanConfig = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<NativeScanConfigResponse> => {
  const payload = await fetchNativeJson<NativeScanConfigPayload>(
    gmp,
    `api/v1/scan-configs/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return {
    scanConfig: nativeScanConfigToModel(payload, {detail: true}),
  };
};

export const fetchNativeScanConfigFamilies = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<NativeScanConfigFamiliesResponse> => {
  const payload = await fetchNativeJson<NativeScanConfigFamiliesPayload>(
    gmp,
    `api/v1/scan-configs/${encodeURIComponent(id)}/families`,
    {token: gmp.session.token},
  );
  return {
    scanConfig: nativeScanConfigFamiliesToModel(payload),
  };
};

export const exportNativeScanConfigMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativeScanConfigPayload>(
    gmp,
    `api/v1/scan-configs/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};

export const cloneNativeScanConfig = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<{id: string}>> => {
  const payload = await writeNativeJson<NativeScanConfigPayload>(
    gmp,
    `api/v1/scan-configs/${encodeURIComponent(id)}/clone`,
    {},
  );
  return new Response({id: stringValue(payload.id)});
};

export const patchNativeScanConfig = async (
  gmp: NativeApiGmp,
  id: string,
  request: NativeScanConfigPatchRequest,
): Promise<Response<{id: string}>> => {
  const payload = await writeNativeJson<NativeScanConfigPayload>(
    gmp,
    `api/v1/scan-configs/${encodeURIComponent(id)}`,
    request,
    'PATCH',
  );
  return new Response({id: stringValue(payload.id)});
};
