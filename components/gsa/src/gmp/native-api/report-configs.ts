/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import Response from 'gmp/http/response';
import type {UrlParams} from 'gmp/http/utils';
import type QueryFilter from 'gmp/models/filter';
import ReportConfig from 'gmp/models/report-config';

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

interface NativeReportConfigParamPayload {
  name: string;
  type: string;
  value: string;
  default: string;
  using_default?: boolean;
  min?: number | null;
  max?: number | null;
  options?: {value: string}[];
  value_report_formats?: NativeReferencePayload[];
  default_report_formats?: NativeReferencePayload[];
}

interface NativeReportConfigPayload {
  id: string;
  name: string;
  comment?: string;
  owner?: {name?: string};
  report_format?: NativeReferencePayload;
  writable?: boolean;
  in_use?: boolean;
  orphan?: boolean;
  alerts?: NativeReferencePayload[];
  params?: NativeReportConfigParamPayload[];
  created_at?: string;
  modified_at?: string;
}

interface NativeReportConfigsPayload {
  page?: Partial<NativePage>;
  items?: NativeReportConfigPayload[];
}

export interface NativeReportConfigsQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
}

export interface NativeReportConfigsResponse {
  reportConfigs: ReportConfig[];
  counts: CollectionCounts;
  page: NativePage;
}

const REPORT_CONFIG_SORT_FIELDS: Record<string, string> = {
  name: 'name',
  report_format: 'report_format',
  created: 'created',
  modified: 'modified',
};

const stringValue = (value: unknown, fallback = ''): string =>
  typeof value === 'string' ? value : fallback;

const integerValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const yesNoValue = (value?: boolean): 0 | 1 => (value === true ? 1 : 0);

const nativeSortFromFilter = (filter?: QueryFilter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending, 'name');
  const nativeField = REPORT_CONFIG_SORT_FIELDS[rawField] ?? rawField;
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

export const nativeReportConfigsQueryFromFilter = (
  filter?: QueryFilter,
): NativeReportConfigsQuery => {
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

const referenceElement = (reference?: NativeReferencePayload) => ({
  _id: stringValue(reference?.id),
  name: stringValue(reference?.name),
});

const reportFormatListValue = (references?: NativeReferencePayload[]) => ({
  report_format: (references ?? []).map(referenceElement),
});

const nativeParamToElement = (param: NativeReportConfigParamPayload) => {
  const usingDefault = yesNoValue(param.using_default);
  const type = {
    __text: stringValue(param.type),
    min: param.min ?? undefined,
    max: param.max ?? undefined,
  };
  if (param.type === 'report_format_list') {
    return {
      name: stringValue(param.name),
      type,
      value: {
        ...reportFormatListValue(param.value_report_formats),
        _using_default: usingDefault,
      },
      default: reportFormatListValue(param.default_report_formats),
      options: {option: []},
    };
  }

  return {
    name: stringValue(param.name),
    type,
    value: {__text: stringValue(param.value), _using_default: usingDefault},
    default: stringValue(param.default),
    options: {option: (param.options ?? []).map(option => option.value)},
  };
};

const nativeReportConfigToModel = (
  item: NativeReportConfigPayload,
): ReportConfig =>
  ReportConfig.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name),
    comment: stringValue(item.comment),
    owner: {name: stringValue(item.owner?.name)},
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    writable: yesNoValue(item.writable ?? true),
    in_use: yesNoValue(item.in_use),
    orphan: yesNoValue(item.orphan),
    permissions: {
      permission: [
        {name: 'get_report_configs'},
        {name: 'modify_report_config'},
        {name: 'delete_report_config'},
      ],
    },
    report_format: referenceElement(item.report_format),
    alerts: {alert: (item.alerts ?? []).map(referenceElement)},
    param: (item.params ?? []).map(nativeParamToElement),
  });

const normalizePage = (
  payloadPage: Partial<NativePage> | undefined,
  query: NativeReportConfigsQuery,
): NativePage => ({
  page: payloadPage?.page ?? query.page,
  page_size: payloadPage?.page_size ?? query.pageSize,
  total: payloadPage?.total ?? 0,
  sort: payloadPage?.sort ?? query.sort,
  filter: payloadPage?.filter ?? query.filter,
});

export const fetchNativeReportConfigs = async (
  gmp: NativeApiGmp,
  query: NativeReportConfigsQuery,
): Promise<NativeReportConfigsResponse> => {
  const payload = await fetchNativeJson<NativeReportConfigsPayload>(
    gmp,
    'api/v1/report-configs',
    {
      token: gmp.session.token,
      page: query.page,
      page_size: query.pageSize,
      sort: query.sort,
      filter: query.filter,
    },
  );
  const page = normalizePage(payload.page, query);
  const reportConfigs = (payload.items ?? []).map(nativeReportConfigToModel);
  return {
    reportConfigs,
    counts: nativeCounts(page, reportConfigs.length),
    page,
  };
};

export const fetchNativeReportConfig = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<ReportConfig> => {
  const payload = await fetchNativeJson<NativeReportConfigPayload>(
    gmp,
    `api/v1/report-configs/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return nativeReportConfigToModel(payload);
};

export const exportNativeReportConfigMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativeReportConfigPayload>(
    gmp,
    `api/v1/report-configs/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};

export const cloneNativeReportConfig = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<{id: string}>> => {
  const payload = await writeNativeJson<NativeReportConfigPayload>(
    gmp,
    `api/v1/report-configs/${encodeURIComponent(id)}/clone`,
    {},
  );
  return new Response({id: stringValue(payload.id)});
};
