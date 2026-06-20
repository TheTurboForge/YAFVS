/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
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

interface NativeNvtPayload {
  id: string;
  oid?: string;
  name?: string;
  comment?: string;
  family?: string;
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
  tags?: string;
  cve_refs?: number;
  cves?: string[];
  cert_refs?: string[];
  xrefs?: string[];
  max_epss?: NativeNvtEpssPayload;
  max_severity?: NativeNvtEpssPayload;
  created_at?: string;
  modified_at?: string;
  updated_at?: string;
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

const NVT_FILTER_FIELDS = [
  'search',
  'family',
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

const nativeNvtToModel = (item: NativeNvtPayload): Nvt => {
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
    nvt: {
      _oid: oid,
      name: stringValue(item.name || oid),
      family: stringValue(item.family),
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
    },
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
  const nvts = (payload.items ?? []).map(nativeNvtToModel);
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
    nvt: nativeNvtToModel(payload),
  };
};
