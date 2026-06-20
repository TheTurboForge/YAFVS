/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import type {UrlParams} from 'gmp/http/utils';
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
  created_at?: string;
  modified_at?: string;
}

interface NativeScannersPayload {
  page?: Partial<NativePage>;
  items?: NativeScannerPayload[];
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

const nativeScannerToModel = (item: NativeScannerPayload): Scanner =>
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
  const scanners = (payload.items ?? []).map(nativeScannerToModel);
  return {
    scanners,
    counts: nativeCounts(page, scanners.length),
    page,
  };
};
