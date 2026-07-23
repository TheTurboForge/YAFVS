/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import Response from 'gmp/http/response';
import type {UrlParams} from 'gmp/http/utils';
import ActionResult from 'gmp/models/action-result';
import Credential, {type CredentialType} from 'gmp/models/credential';
import type QueryFilter from 'gmp/models/filter';

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

interface NativeCredentialUsageReference {
  id: string;
  name: string;
  use_type?: string;
  port?: number | null;
}

interface NativeCredentialPayload {
  id: string;
  name: string;
  comment?: string;
  owner?: string;
  credential_type?: CredentialType;
  allow_insecure?: boolean;
  target_count?: number;
  scanner_count?: number;
  targets?: NativeCredentialUsageReference[];
  scanners?: NativeCredentialUsageReference[];
  created_at?: string;
  modified_at?: string;
}

interface NativeCredentialsPayload {
  page?: Partial<NativePage>;
  items?: NativeCredentialPayload[];
}

interface NativeCredentialPatchArgs {
  id: string;
  name?: string;
  comment?: string;
}

export interface NativeCredentialsQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
  credentialType?: CredentialType;
}

export interface NativeCredentialsResponse {
  credentials: Credential[];
  counts: CollectionCounts;
  page: NativePage;
}

const CREDENTIAL_SORT_FIELDS: Record<string, string> = {
  name: 'name',
  type: 'credential_type',
  credentialType: 'credential_type',
  credential_type: 'credential_type',
  login: 'name',
  owner: 'owner',
  modified: 'modified',
};

const nativeCredentialTypeFromFilter = (
  filter?: QueryFilter,
): CredentialType | undefined => {
  const value = filter?.get('type') ?? filter?.get('credential_type');
  return typeof value === 'string' ? (value as CredentialType) : undefined;
};

const CREDENTIAL_PERMISSIONS = [
  'get_credentials',
  'create_credential',
  'modify_credential',
  'delete_credential',
] as const;

const stringValue = (value: unknown): string =>
  typeof value === 'string' ? value : '';

const integerValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const yesNoValue = (value?: boolean): 0 | 1 => (value === false ? 0 : 1);

const nativeSortFromFilter = (filter?: QueryFilter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending) || 'name';
  const nativeField = CREDENTIAL_SORT_FIELDS[rawField] ?? rawField;
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

export const nativeCredentialsQueryFromFilter = (
  filter?: QueryFilter,
): NativeCredentialsQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
    credentialType: nativeCredentialTypeFromFilter(filter),
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
  method = 'POST',
): Promise<T> => {
  const response = await fetch(gmp.buildUrl(path), {
    method,
    credentials: 'include',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...(gmp.session.token ? {'X-YAFVS-Token': gmp.session.token} : {}),
      ...(gmp.session.jwt ? {Authorization: `Bearer ${gmp.session.jwt}`} : {}),
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }

  return (await response.json()) as T;
};

const referenceElement = (reference: NativeCredentialUsageReference) => ({
  _id: stringValue(reference.id),
  name: stringValue(reference.name),
  port: reference.port ?? undefined,
  usage_type: stringValue(reference.use_type),
});

const nativeCredentialToModel = (item: NativeCredentialPayload): Credential =>
  Credential.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name),
    comment: stringValue(item.comment),
    owner: {name: stringValue(item.owner)},
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    type: item.credential_type,
    writable: yesNoValue(true),
    in_use: item.target_count || item.scanner_count ? 1 : 0,
    targets: {target: (item.targets ?? []).map(referenceElement)},
    scanners: {scanner: (item.scanners ?? []).map(referenceElement)},
    permissions: {
      permission: CREDENTIAL_PERMISSIONS.map(name => ({name})),
    },
  });

const normalizePage = (
  payloadPage: Partial<NativePage> | undefined,
  query: NativeCredentialsQuery,
): NativePage => ({
  page: payloadPage?.page ?? query.page,
  page_size: payloadPage?.page_size ?? query.pageSize,
  total: payloadPage?.total ?? 0,
  sort: payloadPage?.sort ?? query.sort,
  filter: payloadPage?.filter ?? query.filter,
});

export const fetchNativeCredentials = async (
  gmp: NativeApiGmp,
  query: NativeCredentialsQuery,
): Promise<NativeCredentialsResponse> => {
  const payload = await fetchNativeJson<NativeCredentialsPayload>(
    gmp,
    'api/v1/credentials',
    {
      token: gmp.session.token,
      page: query.page,
      page_size: query.pageSize,
      sort: query.sort,
      filter: query.filter,
      ...(query.credentialType ? {credential_type: query.credentialType} : {}),
    },
  );
  const page = normalizePage(payload.page, query);
  const credentials = (payload.items ?? []).map(nativeCredentialToModel);
  return {
    credentials,
    counts: nativeCounts(page, credentials.length),
    page,
  };
};

export const fetchNativeCredential = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Credential> => {
  const payload = await fetchNativeJson<NativeCredentialPayload>(
    gmp,
    `api/v1/credentials/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return nativeCredentialToModel(payload);
};

export const fetchNativeCredentialPublicKey = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<ArrayBuffer> => {
  const response = await fetch(
    gmp.buildUrl(`api/v1/credentials/${encodeURIComponent(id)}/public-key`, {
      token: gmp.session.token,
    }),
    {
      credentials: 'include',
      headers: {
        Accept: 'application/key',
        ...(gmp.session.jwt
          ? {Authorization: `Bearer ${gmp.session.jwt}`}
          : {}),
      },
    },
  );

  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }

  return response.arrayBuffer();
};

export const deleteNativeCredential = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<void> => {
  const response = await fetch(
    gmp.buildUrl(`api/v1/credentials/${encodeURIComponent(id)}`),
    {
      method: 'DELETE',
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        ...(gmp.session.token ? {'X-YAFVS-Token': gmp.session.token} : {}),
        ...(gmp.session.jwt
          ? {Authorization: `Bearer ${gmp.session.jwt}`}
          : {}),
      },
    },
  );
  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }
};

export const exportNativeCredentialMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativeCredentialPayload>(
    gmp,
    `api/v1/credentials/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};

export const exportNativeCredentialsMetadata = async (
  gmp: NativeApiGmp,
  ids: string[],
): Promise<Response<string>> => {
  const credentials = await Promise.all(
    ids.map(async id => {
      const payload = await fetchNativeJson<NativeCredentialPayload>(
        gmp,
        `api/v1/credentials/${encodeURIComponent(id)}/export`,
        {token: gmp.session.token},
      );
      return payload;
    }),
  );
  return new Response(`${JSON.stringify({credentials}, null, 2)}\n`);
};

export const patchNativeCredential = async (
  gmp: NativeApiGmp,
  {id, name, comment}: NativeCredentialPatchArgs,
): Promise<Response<ActionResult>> => {
  const body = {
    ...(name !== undefined ? {name} : {}),
    ...(comment !== undefined ? {comment} : {}),
  };
  const payload = await writeNativeJson<NativeCredentialPayload>(
    gmp,
    `api/v1/credentials/${encodeURIComponent(id)}`,
    body,
    'PATCH',
  );
  return new Response(
    new ActionResult({
      action_result: {
        action: 'save_credential',
        id: stringValue(payload.id),
        message: 'OK',
      },
    }),
  );
};

export const cloneNativeCredential = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<{id: string}>> => {
  const payload = await writeNativeJson<NativeCredentialPayload>(
    gmp,
    `api/v1/credentials/${encodeURIComponent(id)}/clone`,
    {},
  );
  return new Response({id: stringValue(payload.id)});
};
