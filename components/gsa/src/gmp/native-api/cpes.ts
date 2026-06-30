/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import type {UrlParams} from 'gmp/http/utils';
import Cpe from 'gmp/models/cpe';
import type Filter from 'gmp/models/filter';
import {NO_VALUE, YES_VALUE} from 'gmp/parser';

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

interface NativeCatalogCpeCvePayload {
  id: string;
  severity?: number;
}

interface NativeCatalogCpeReferencePayload {
  url?: string;
}

interface NativeUserTagPayload {
  id: string;
  name: string;
  value: string;
  comment: string;
}

interface NativeCatalogCpePayload {
  id: string;
  name?: string;
  comment?: string;
  title?: string;
  cpe_name_id?: string;
  deprecated?: boolean;
  deprecated_by?: string;
  severity?: number;
  cve_refs?: number;
  cves?: NativeCatalogCpeCvePayload[];
  references?: NativeCatalogCpeReferencePayload[];
  user_tags?: NativeUserTagPayload[];
  created_at?: string;
  modified_at?: string;
  updated_at?: string;
}

interface NativeCpesPayload {
  page?: Partial<NativePage>;
  items?: NativeCatalogCpePayload[];
}

export interface NativeCpesQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
}

export interface NativeCpesResponse {
  cpes: Cpe[];
  counts: CollectionCounts;
  page: NativePage;
}

const CPE_SORT_FIELDS: Record<string, string> = {
  name: 'name',
  title: 'title',
  modified: 'modified',
  cves: 'cves',
  severity: 'severity',
  cpeNameId: 'cpeNameId',
  cpe_name_id: 'cpe_name_id',
  deprecated: 'deprecated',
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
  const rawField = stringValue(reverse ?? ascending) || 'modified';
  const nativeField = CPE_SORT_FIELDS[rawField] ?? rawField;
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

export const nativeCpesQueryFromFilter = (filter?: Filter): NativeCpesQuery => {
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

const nativeCpeReferencesElement = (
  references: NativeCatalogCpeReferencePayload[] = [],
) => {
  const referenceElements = references
    .map(reference => stringValue(reference.url))
    .filter(url => url.length > 0)
    .map(url => ({__text: url, _href: url}));
  return referenceElements.length > 0 ? {reference: referenceElements} : undefined;
};

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

const nativeCpeToModel = (
  item: NativeCatalogCpePayload,
  {detail = false}: {detail?: boolean} = {},
): Cpe =>
  Cpe.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name || item.id),
    comment: stringValue(item.comment),
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    update_time: stringValue(item.updated_at || item.modified_at),
    cpe: {
      title: stringValue(item.title),
      cpe_name_id: stringValue(item.cpe_name_id),
      deprecated: item.deprecated ? YES_VALUE : NO_VALUE,
      deprecated_by: item.deprecated_by
        ? {_cpe_id: stringValue(item.deprecated_by)}
        : undefined,
      severity: numberValue(item.severity),
      cve_refs: integerValue(item.cve_refs),
      cves: {
        cve: (item.cves ?? []).map(cve => ({
          entry: {
            _id: cve.id,
            cvss: {base_metrics: {score: numberValue(cve.severity)}},
          },
        })),
      },
      references: detail ? nativeCpeReferencesElement(item.references ?? []) : undefined,
    },
    user_tags: detail ? nativeUserTagsElement(item.user_tags ?? []) : undefined,
  });

export const fetchNativeCpes = async (
  gmp: NativeApiGmp,
  query: NativeCpesQuery,
): Promise<NativeCpesResponse> => {
  const payload = await fetchNativeJson<NativeCpesPayload>(
    gmp,
    'api/v1/cpes',
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
  const cpes = (payload.items ?? []).map(item => nativeCpeToModel(item));
  return {
    cpes,
    counts: nativeCounts(page, cpes.length),
    page,
  };
};

export const fetchNativeCpe = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Cpe> => {
  const payload = await fetchNativeJson<NativeCatalogCpePayload>(
    gmp,
    `api/v1/cpes/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return nativeCpeToModel(payload, {detail: true});
};
