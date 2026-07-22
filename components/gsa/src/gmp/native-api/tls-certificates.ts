/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import Response from 'gmp/http/response';
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

interface NativeUserTagPayload {
  id: string;
  name: string;
  value: string;
  comment: string;
}

interface NativeTlsCertificateSourceLocationPayload {
  id: string;
  host_ip?: string;
  port?: string;
  host_asset_id?: string;
}

interface NativeTlsCertificateSourceOriginPayload {
  id: string;
  origin_type?: string;
  origin_id?: string;
  origin_data?: string;
}

interface NativeTlsCertificateSourcePayload {
  id: string;
  timestamp?: string;
  tls_versions?: string;
  location?: NativeTlsCertificateSourceLocationPayload;
  origin?: NativeTlsCertificateSourceOriginPayload;
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
  valid?: boolean;
  trust?: boolean;
  time_status?: string;
  source_host_count?: number;
  source_port_count?: number;
  source_count?: number;
  in_use?: boolean;
  writable: boolean;
  sources?: NativeTlsCertificateSourcePayload[];
  user_tags?: NativeUserTagPayload[];
  created_at?: string;
  modified_at?: string;
}

interface NativeTlsCertificatesPayload {
  page?: Partial<NativePage>;
  items?: NativeTlsCertificatePayload[];
}

interface NativeTlsCertificatePemPayload {
  id?: string;
  certificate?: string;
}

type NativeTlsCertificateTimeStatus =
  | 'inactive'
  | 'valid'
  | 'expired'
  | 'unknown';

export interface NativeTlsCertificateResponse {
  tlsCertificate: TlsCertificate;
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

const booleanToYesNo = (value: unknown): 1 | 0 | undefined =>
  typeof value === 'boolean' ? (value ? 1 : 0) : undefined;

const nativeTimeStatus = (
  value: unknown,
): NativeTlsCertificateTimeStatus | undefined =>
  value === 'inactive' ||
  value === 'valid' ||
  value === 'expired' ||
  value === 'unknown'
    ? value
    : undefined;

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

const deleteNative = async (gmp: NativeApiGmp, path: string): Promise<void> => {
  const response = await fetch(gmp.buildUrl(path), {
    method: 'DELETE',
    credentials: 'include',
    headers: {
      Accept: 'application/json',
      ...(gmp.session.token ? {'X-YAFVS-Token': gmp.session.token} : {}),
      ...(gmp.session.jwt ? {Authorization: `Bearer ${gmp.session.jwt}`} : {}),
    },
  });

  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }
};

const nativeUserTagsElement = (tags: NativeUserTagPayload[] = []) => ({
  tag: tags.map(tag => ({
    _id: stringValue(tag.id),
    name: stringValue(tag.name),
    value: stringValue(tag.value),
    comment: stringValue(tag.comment),
  })),
});

const nativeSourceToElement = (source: NativeTlsCertificateSourcePayload) => ({
  _id: stringValue(source.id),
  timestamp: stringValue(source.timestamp),
  tls_versions: stringValue(source.tls_versions),
  location: source.location
    ? {
        _id: stringValue(source.location.id),
        host: source.location.host_asset_id
          ? {
              asset: {_id: stringValue(source.location.host_asset_id)},
              ip: stringValue(source.location.host_ip),
            }
          : undefined,
        port: stringValue(source.location.port),
      }
    : undefined,
  origin: source.origin
    ? {
        _id: stringValue(source.origin.id),
        origin_type: stringValue(source.origin.origin_type),
        origin_id: stringValue(source.origin.origin_id),
        origin_data: stringValue(source.origin.origin_data),
        report:
          source.origin.origin_type === 'Report'
            ? {
                _id: stringValue(source.origin.origin_id),
                date: stringValue(source.timestamp),
              }
            : undefined,
      }
    : undefined,
});

const nativeTlsCertificateToModel = (
  item: NativeTlsCertificatePayload,
  {detail = false}: {detail?: boolean} = {},
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
    valid: detail ? booleanToYesNo(item.valid) : undefined,
    trust: detail ? booleanToYesNo(item.trust) : undefined,
    time_status: detail ? nativeTimeStatus(item.time_status) : undefined,
    writable: booleanToYesNo(item.writable),
    user_tags: detail ? nativeUserTagsElement(item.user_tags ?? []) : undefined,
    sources: detail
      ? {source: (item.sources ?? []).map(nativeSourceToElement)}
      : undefined,
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
  const tlsCertificates = (payload.items ?? []).map(item =>
    nativeTlsCertificateToModel(item),
  );
  return {
    tlsCertificates,
    counts: nativeCounts(page, tlsCertificates.length),
    page,
  };
};

export const fetchNativeTlsCertificate = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<NativeTlsCertificateResponse> => {
  const payload = await fetchNativeJson<NativeTlsCertificatePayload>(
    gmp,
    `api/v1/tls-certificates/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return {
    tlsCertificate: nativeTlsCertificateToModel(payload, {detail: true}),
  };
};

export const exportNativeTlsCertificateMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativeTlsCertificatePayload>(
    gmp,
    `api/v1/tls-certificates/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};

export const deleteNativeTlsCertificate = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<void> =>
  deleteNative(gmp, `api/v1/tls-certificates/${encodeURIComponent(id)}`);

export const fetchNativeTlsCertificatePem = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<TlsCertificate>> => {
  const payload = await fetchNativeJson<NativeTlsCertificatePemPayload>(
    gmp,
    `api/v1/tls-certificates/${encodeURIComponent(id)}/certificate`,
    {token: gmp.session.token},
  );
  return new Response(
    TlsCertificate.fromElement({
      _id: stringValue(payload.id),
      certificate: {__text: stringValue(payload.certificate)},
    }),
  );
};

export const exportNativeTlsCertificatesMetadata = async (
  gmp: NativeApiGmp,
  ids: string[],
): Promise<Response<string>> => {
  const tlsCertificates = await Promise.all(
    ids.map(async id => {
      const payload = await fetchNativeJson<NativeTlsCertificatePayload>(
        gmp,
        `api/v1/tls-certificates/${encodeURIComponent(id)}/export`,
        {token: gmp.session.token},
      );
      return payload;
    }),
  );
  return new Response(
    `${JSON.stringify({tls_certificates: tlsCertificates}, null, 2)}\n`,
  );
};
