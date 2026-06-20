/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import type {UrlParams} from 'gmp/http/utils';
import CertBundAdv from 'gmp/models/cert-bund';
import type Filter from 'gmp/models/filter';

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

interface NativeCertBundAdvisoryPayload {
  id: string;
  name?: string;
  comment?: string;
  title?: string;
  summary?: string;
  severity?: number;
  cve_refs?: number;
  cves?: string[];
  created_at?: string;
  modified_at?: string;
  updated_at?: string;
}

interface NativeCertBundAdvisoriesPayload {
  page?: Partial<NativePage>;
  items?: NativeCertBundAdvisoryPayload[];
}

export interface NativeCertBundAdvisoriesQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
}

export interface NativeCertBundAdvisoriesResponse {
  certbunds: CertBundAdv[];
  counts: CollectionCounts;
  page: NativePage;
}

const CERT_BUND_SORT_FIELDS: Record<string, string> = {
  name: 'name',
  title: 'title',
  created: 'created',
  modified: 'modified',
  cves: 'cves',
  severity: 'severity',
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
  const rawField = stringValue(reverse ?? ascending) || 'created';
  const nativeField = CERT_BUND_SORT_FIELDS[rawField] ?? rawField;
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

export const nativeCertBundAdvisoriesQueryFromFilter = (
  filter?: Filter,
): NativeCertBundAdvisoriesQuery => {
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

const nativeCertBundAdvisoryToModel = (
  item: NativeCertBundAdvisoryPayload,
): CertBundAdv =>
  CertBundAdv.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name || item.id),
    comment: stringValue(item.comment),
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    update_time: stringValue(item.updated_at || item.modified_at),
    cert_bund_adv: {
      cve_refs: integerValue(item.cve_refs),
      severity: numberValue(item.severity),
      summary: stringValue(item.summary),
      title: stringValue(item.title),
      raw_data: {
        Advisory: {
          CVEList: {
            CVE: item.cves ?? [],
          },
          Ref_Num: {
            __text: stringValue(item.name || item.id),
            _update: stringValue(item.updated_at || item.modified_at),
          },
        },
      },
    },
  });

export const fetchNativeCertBundAdvisories = async (
  gmp: NativeApiGmp,
  query: NativeCertBundAdvisoriesQuery,
): Promise<NativeCertBundAdvisoriesResponse> => {
  const payload = await fetchNativeJson<NativeCertBundAdvisoriesPayload>(
    gmp,
    'api/v1/cert-bund-advisories',
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
  const certbunds = (payload.items ?? []).map(nativeCertBundAdvisoryToModel);
  return {
    certbunds,
    counts: nativeCounts(page, certbunds.length),
    page,
  };
};
