/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import Response from 'gmp/http/response';
import type {UrlParams} from 'gmp/http/utils';
import type Filter from 'gmp/models/filter';
import Nvt from 'gmp/models/nvt';

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

interface NativeNvtEpssPayload {
  score?: number;
  percentile?: number;
  cve?: string;
  severity?: number;
}

interface NativeUserTagPayload {
  id: string;
  name: string;
  value: string;
  comment: string;
}

interface NativeNvtPayload {
  id: string;
  oid?: string;
  name?: string;
  comment?: string;
  family?: string;
  category?: string;
  discovery?: number;
  severity?: number;
  qod?: number;
  qod_type?: string;
  solution_type?: string;
  solution_method?: string;
  solution?: string;
  summary?: string;
  insight?: string;
  affected?: string;
  impact?: string;
  detection?: string;
  default_timeout?: string;
  preferences?: NativeNvtPreferencePayload[];
  tags?: string;
  cve_refs?: number;
  cves?: string[];
  cert_refs?: string[];
  xrefs?: string[];
  user_tags?: NativeUserTagPayload[];
  max_epss?: NativeNvtEpssPayload;
  max_severity?: NativeNvtEpssPayload;
  created_at?: string;
  modified_at?: string;
  updated_at?: string;
}

interface NativeNvtPreferencePayload {
  id?: number;
  name?: string;
  hr_name?: string;
  type?: string;
  value?: string;
  default?: string;
}

interface NativeNvtsPayload {
  page?: Partial<NativePage>;
  items?: NativeNvtPayload[];
}

export interface NativeNvtsQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
}

export interface NativeNvtsResponse {
  nvts: Nvt[];
  counts: CollectionCounts;
  page: NativePage;
}

export interface NativeNvtResponse {
  nvt: Nvt;
}

const NVT_SORT_FIELDS: Record<string, string> = {
  name: 'name',
  family: 'family',
  category: 'category',
  discovery: 'discovery',
  created: 'created',
  modified: 'modified',
  cve: 'cve',
  severity: 'severity',
  qod: 'qod',
  qod_type: 'qod_type',
  solution_type: 'solution_type',
  epss_score: 'epss_score',
  epss_percentile: 'epss_percentile',
};

const nativePreferenceToElement = (preference: NativeNvtPreferencePayload) => {
  const type = stringValue(preference.type);
  let value = stringValue(preference.value);
  let defaultValue = stringValue(preference.default);
  let alt: string[] | undefined;

  if (type === 'radio') {
    const values = defaultValue.split(';').filter(part => part !== '');
    value = values[0] ?? value;
    defaultValue = values[0] ?? defaultValue;
    alt = values.filter(part => part !== value);
  }

  return {
    id: integerValue(preference.id),
    name: stringValue(preference.name),
    hr_name: stringValue(preference.hr_name),
    type,
    value,
    default: defaultValue,
    alt,
  };
};

const NVT_FILTER_FIELDS = [
  'search',
  'family',
  'category',
  'discovery',
  'name',
  'cve',
  'qod_type',
  'solution_type',
];

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
  const rawField = stringValue(reverse ?? ascending) || 'created';
  const nativeField = NVT_SORT_FIELDS[rawField] ?? rawField;
  return reverse !== undefined ? `-${nativeField}` : nativeField;
};

const nativeSearchFromFilter = (filter?: Filter): string => {
  const search = filter?.get('search');
  if (search !== undefined) {
    return String(search);
  }
  for (const field of NVT_FILTER_FIELDS.filter(field => field !== 'search')) {
    const value = filter?.get(field);
    if (value !== undefined) {
      return `${field}=${String(value)}`;
    }
  }
  const criteria = filter?.toFilterCriteriaString().trim() ?? '';
  return /[=<>:~]/.test(criteria) ? '' : criteria;
};

export const nativeNvtsQueryFromFilter = (filter?: Filter): NativeNvtsQuery => {
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

const refFromNative = (value: string) => {
  const separator = value.indexOf(':');
  if (separator <= 0) {
    return {_id: value, _type: 'other'};
  }
  return {
    _type: value.slice(0, separator),
    _id: value.slice(separator + 1),
  };
};

const epssFromNative = (value?: NativeNvtEpssPayload) =>
  value
    ? {
        score: numberValue(value.score),
        percentile: numberValue(value.percentile),
        cve: {
          _id: stringValue(value.cve),
          severity: numberValue(value.severity),
        },
      }
    : undefined;

const detailTagsFromNative = (item: NativeNvtPayload): string => {
  const parts = [stringValue(item.tags)].filter(part => part !== '');
  const detailTags = [
    ['summary', item.summary],
    ['insight', item.insight],
    ['affected', item.affected],
    ['impact', item.impact],
    ['vuldetect', item.detection],
  ];
  for (const [key, value] of detailTags) {
    const stringified = stringValue(value);
    if (stringified !== '') {
      parts.push(`${key}=${stringified}`);
    }
  }
  return parts.join('|');
};

const nativeNvtToModel = (
  item: NativeNvtPayload,
  {detail = false}: {detail?: boolean} = {},
): Nvt => {
  const oid = stringValue(item.oid || item.id);
  const cves = item.cves ?? [];
  const refs = [
    ...cves.map(cve => ({_id: cve, _type: 'cve'})),
    ...(item.cert_refs ?? []).map(refFromNative),
    ...(item.xrefs ?? []).map(refFromNative),
  ];
  const maxEpss = epssFromNative(item.max_epss);
  const maxSeverity = epssFromNative(item.max_severity);
  return Nvt.fromElement({
    _id: oid,
    name: stringValue(item.name || oid),
    comment: stringValue(item.comment),
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    update_time: stringValue(item.updated_at || item.modified_at),
    writable: detail ? 1 : undefined,
    nvt: {
      _oid: oid,
      name: stringValue(item.name || oid),
      family: stringValue(item.family),
      category: stringValue(item.category),
      discovery: integerValue(item.discovery),
      default_timeout: item.default_timeout,
      cvss_base: numberValue(item.severity),
      tags: detailTagsFromNative(item),
      qod: {
        value: numberValue(item.qod),
        type: stringValue(item.qod_type),
      },
      refs: {
        ref: refs,
      },
      solution: {
        _type: stringValue(item.solution_type),
        _method: stringValue(item.solution_method),
        __text: stringValue(item.solution),
      },
      epss: maxEpss || maxSeverity
        ? {
            max_severity: maxSeverity,
            max_epss: maxEpss,
          }
        : undefined,
      preferences: detail
        ? {
            preference: (item.preferences ?? []).map(nativePreferenceToElement),
          }
        : undefined,
    },
    user_tags: detail ? nativeUserTagsElement(item.user_tags ?? []) : undefined,
  });
};

export const fetchNativeNvts = async (
  gmp: NativeApiGmp,
  query: NativeNvtsQuery,
): Promise<NativeNvtsResponse> => {
  const payload = await fetchNativeJson<NativeNvtsPayload>(gmp, 'api/v1/nvts', {
    token: gmp.session.token,
    page: query.page,
    page_size: query.pageSize,
    sort: query.sort,
    filter: query.filter,
  });
  const page = {
    page: integerValue(payload.page?.page, 1),
    page_size: integerValue(payload.page?.page_size, query.pageSize),
    total: integerValue(payload.page?.total),
    sort: stringValue(payload.page?.sort),
    filter: stringValue(payload.page?.filter),
  };
  const nvts = (payload.items ?? []).map(item => nativeNvtToModel(item));
  return {
    nvts,
    counts: nativeCounts(page, nvts.length),
    page,
  };
};

export const fetchNativeNvt = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<NativeNvtResponse> => {
  const payload = await fetchNativeJson<NativeNvtPayload>(
    gmp,
    `api/v1/nvts/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return {
    nvt: nativeNvtToModel(payload, {detail: true}),
  };
};

export const exportNativeNvtMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativeNvtPayload>(
    gmp,
    `api/v1/nvts/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};

export const exportNativeNvtsMetadata = async (
  gmp: NativeApiGmp,
  ids: string[],
): Promise<Response<string>> => {
  const nvts = await Promise.all(
    ids.map(async id => {
      const payload = await fetchNativeJson<NativeNvtPayload>(
        gmp,
        `api/v1/nvts/${encodeURIComponent(id)}/export`,
        {token: gmp.session.token},
      );
      return payload;
    }),
  );
  return new Response(`${JSON.stringify({nvts}, null, 2)}\n`);
};
