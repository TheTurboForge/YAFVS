/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import Response from 'gmp/http/response';
import type {UrlParams} from 'gmp/http/utils';
import ReportFormat from 'gmp/models/report-format';
import type QueryFilter from 'gmp/models/filter';
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

interface NativeReferencePayload {
  id: string;
  name: string;
}

interface NativeReportFormatPayload {
  id: string;
  name: string;
  summary?: string;
  description?: string;
  extension?: string;
  content_type?: string;
  report_type?: string;
  trust?: string;
  trust_time?: string;
  active?: boolean;
  predefined?: boolean;
  configurable?: boolean;
  deprecated?: boolean;
  alerts?: NativeReferencePayload[];
  params?: NativeReportFormatParamPayload[];
  created_at?: string;
  modified_at?: string;
}

interface NativeReportFormatParamPayload {
  name: string;
  type?: string;
  param_type?: string;
  value?: string;
  default?: string;
  min?: number | null;
  max?: number | null;
  options?: {value: string}[];
}

interface NativeReportFormatsPayload {
  page?: Partial<NativePage>;
  items?: NativeReportFormatPayload[];
}

export interface NativeReportFormatsQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
}

export interface NativeReportFormatsResponse {
  reportFormats: ReportFormat[];
  counts: CollectionCounts;
  page: NativePage;
}

const REPORT_FORMAT_SORT_FIELDS: Record<string, string> = {
  name: 'name',
  extension: 'extension',
  content_type: 'content_type',
  trust: 'trust',
  active: 'active',
  predefined: 'predefined',
  created: 'created',
  modified: 'modified',
};

const stringValue = (value: unknown, fallback = ''): string =>
  typeof value === 'string' && value.length > 0 ? value : fallback;

const integerValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const yesNoValue = (value: unknown): YesNo =>
  value === true ? YES_VALUE : NO_VALUE;

const nativeSortFromFilter = (filter?: QueryFilter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending, 'name');
  const nativeField = REPORT_FORMAT_SORT_FIELDS[rawField] ?? rawField;
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

export const nativeReportFormatsQueryFromFilter = (
  filter?: QueryFilter,
): NativeReportFormatsQuery => {
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

const referenceElement = (reference: NativeReferencePayload) => ({
  _id: stringValue(reference.id),
  name: stringValue(reference.name),
});

const csvReferenceElements = (value?: string) =>
  stringValue(value)
    .split(',')
    .map(reference => reference.trim())
    .filter(reference => reference.length > 0)
    .map(reference => ({_id: reference}));

const nativeReportFormatParamToElement = (
  param: NativeReportFormatParamPayload,
) => {
  const paramType = stringValue(param.type ?? param.param_type, 'string');
  const type = {
    __text: paramType,
    min: param.min ?? undefined,
    max: param.max ?? undefined,
  };
  if (paramType === 'report_format_list') {
    return {
      name: stringValue(param.name),
      type,
      value: {report_format: csvReferenceElements(param.value)},
      default: {report_format: csvReferenceElements(param.default)},
      options: {option: []},
    };
  }

  const value = stringValue(
    param.value,
    paramType === 'multi_selection' ? '[]' : '',
  );
  const defaultValue = stringValue(
    param.default,
    paramType === 'multi_selection' ? '[]' : '',
  );

  return {
    name: stringValue(param.name),
    type,
    value: {__text: value},
    default: defaultValue,
    options: {option: (param.options ?? []).map(option => option.value)},
  };
};

const nativeReportFormatToModel = (
  item: NativeReportFormatPayload,
): ReportFormat =>
  ReportFormat.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name),
    summary: stringValue(item.summary),
    extension: stringValue(item.extension),
    content_type: stringValue(item.content_type),
    report_type: stringValue(item.report_type),
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    active: yesNoValue(item.active),
    predefined: yesNoValue(item.predefined),
    configurable: yesNoValue(item.configurable),
    deprecated: item.deprecated,
    trust: {
      __text: stringValue(item.trust, 'unknown'),
      time: stringValue(item.trust_time),
    },
    alerts: {
      alert: (item.alerts ?? []).map(referenceElement),
    },
    param: (item.params ?? []).map(nativeReportFormatParamToElement),
  });

const normalizePage = (
  payloadPage: Partial<NativePage> | undefined,
  query: NativeReportFormatsQuery,
): NativePage => ({
  page: payloadPage?.page ?? query.page,
  page_size: payloadPage?.page_size ?? query.pageSize,
  total: payloadPage?.total ?? 0,
  sort: payloadPage?.sort ?? query.sort,
  filter: payloadPage?.filter ?? query.filter,
});

export const fetchNativeReportFormats = async (
  gmp: NativeApiGmp,
  query: NativeReportFormatsQuery,
): Promise<NativeReportFormatsResponse> => {
  const payload = await fetchNativeJson<NativeReportFormatsPayload>(
    gmp,
    'api/v1/report-formats',
    {
      token: gmp.session.token,
      page: query.page,
      page_size: query.pageSize,
      sort: query.sort,
      filter: query.filter,
    },
  );
  const page = normalizePage(payload.page, query);
  const reportFormats = (payload.items ?? []).map(nativeReportFormatToModel);
  return {
    reportFormats,
    counts: nativeCounts(page, reportFormats.length),
    page,
  };
};

export const fetchNativeReportFormat = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<ReportFormat> => {
  const payload = await fetchNativeJson<NativeReportFormatPayload>(
    gmp,
    `api/v1/report-formats/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return nativeReportFormatToModel(payload);
};

export const exportNativeReportFormatMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativeReportFormatPayload>(
    gmp,
    `api/v1/report-formats/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};

export const exportNativeReportFormatsMetadata = async (
  gmp: NativeApiGmp,
  ids: string[],
): Promise<Response<string>> => {
  const reportFormats = await Promise.all(
    ids.map(async id => {
      const payload = await fetchNativeJson<NativeReportFormatPayload>(
        gmp,
        `api/v1/report-formats/${encodeURIComponent(id)}/export`,
        {token: gmp.session.token},
      );
      return payload;
    }),
  );
  return new Response(
    `${JSON.stringify({report_formats: reportFormats}, null, 2)}\n`,
  );
};
