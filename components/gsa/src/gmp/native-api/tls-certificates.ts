/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import type {UrlParams} from 'gmp/http/utils';
import type Filter from 'gmp/models/filter';
import TlsCertificate from 'gmp/models/tls-certificate';

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

interface NativeTlsCertificatePayload {
  id: string;
  name: string;
  comment?: string;
  subject_dn?: string;
  issuer_dn?: string;
  serial?: string;
  md5_fingerprint?: string;
  sha256_fingerprint?: string;
  activation_time?: string;
  expiration_time?: string;
  last_seen?: string;
  source_host_count?: number;
  source_port_count?: number;
  source_count?: number;
  in_use?: boolean;
  created_at?: string;
  modified_at?: string;
}

interface NativeTlsCertificatesPayload {
  page?: Partial<NativePage>;
  items?: NativeTlsCertificatePayload[];
}

export interface NativeTlsCertificatesQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
}

export interface NativeTlsCertificatesResponse {
  tlsCertificates: TlsCertificate[];
  counts: CollectionCounts;
  page: NativePage;
}

const TLS_CERTIFICATE_SORT_FIELDS: Record<string, string> = {
  subject_dn: 'subject_dn',
  subject: 'subject_dn',
  serial: 'serial',
  activates: 'activation_time',
  activation_time: 'activation_time',
  expires: 'expiration_time',
  expiration_time: 'expiration_time',
  last_seen: 'last_seen',
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
  const rawField = stringValue(reverse ?? ascending) || 'last_seen';
  const nativeField = TLS_CERTIFICATE_SORT_FIELDS[rawField] ?? rawField;
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

export const nativeTlsCertificatesQueryFromFilter = (
  filter?: Filter,
): NativeTlsCertificatesQuery => {
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

const nativeTlsCertificateToModel = (
  item: NativeTlsCertificatePayload,
): TlsCertificate =>
  TlsCertificate.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name),
    comment: stringValue(item.comment),
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    subject_dn: stringValue(item.subject_dn),
    issuer_dn: stringValue(item.issuer_dn),
    serial: stringValue(item.serial),
    md5_fingerprint: stringValue(item.md5_fingerprint),
    sha256_fingerprint: stringValue(item.sha256_fingerprint),
    activation_time: stringValue(item.activation_time),
    expiration_time: stringValue(item.expiration_time),
    last_seen: stringValue(item.last_seen),
    in_use: item.in_use ? 1 : 0,
  });

export const fetchNativeTlsCertificates = async (
  gmp: NativeApiGmp,
  query: NativeTlsCertificatesQuery,
): Promise<NativeTlsCertificatesResponse> => {
  const payload = await fetchNativeJson<NativeTlsCertificatesPayload>(
    gmp,
    'api/v1/tls-certificates',
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
  const tlsCertificates = (payload.items ?? []).map(nativeTlsCertificateToModel);
  return {
    tlsCertificates,
    counts: nativeCounts(page, tlsCertificates.length),
    page,
  };
};
