/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import Response from 'gmp/http/response';
import type {UrlParams} from 'gmp/http/utils';
import ActionResult from 'gmp/models/action-result';
import type Filter from 'gmp/models/filter';
import Target, {type AliveTest, type SshHostKeyPin} from 'gmp/models/target';

interface NativeApiSession {
  readonly jwt?: string;
  readonly token?: string;
}

interface NativeApiGmp {
  readonly session: NativeApiSession;
  buildUrl(path: string, params?: UrlParams): string;
}

interface NativeReference {
  id?: string;
  name?: string;
}

interface NativeCredentialReference extends NativeReference {
  credential_type?: string;
  port?: number | null;
  host_key_pins?: SshHostKeyPin[];
}

interface NativeTargetCredentials {
  ssh?: NativeCredentialReference;
  ssh_elevate?: NativeCredentialReference;
  smb?: NativeCredentialReference;
  esxi?: NativeCredentialReference;
  snmp?: NativeCredentialReference;
  krb5?: NativeCredentialReference;
}

interface NativeUserTagPayload {
  id: string;
  name: string;
  value: string;
  comment: string;
}

interface NativeTargetItem {
  id?: string;
  name?: string;
  comment?: string;
  hosts?: string[];
  exclude_hosts?: string[];
  max_hosts?: number;
  alive_tests?: string[];
  allow_simultaneous_ips?: boolean;
  reverse_lookup_only?: boolean;
  reverse_lookup_unify?: boolean;
  port_list?: NativeReference;
  credentials?: NativeTargetCredentials;
  task_count?: number;
  tasks?: NativeReference[];
  user_tags?: NativeUserTagPayload[];
  creation_time?: string;
  modification_time?: string;
}

interface NativeTargetPage {
  page: number;
  page_size: number;
  total: number;
  sort: string;
  filter: string;
}

interface NativeTargetCollectionPayload {
  page?: Partial<NativeTargetPage>;
  items?: NativeTargetItem[];
}

export interface NativeTargetPatchArgs {
  id: string;
  name?: string;
  comment?: string;
  aliveTests?: AliveTest[];
  allowSimultaneousIPs?: boolean;
  credentials?: NativeTargetCredentialsPatchArgs;
  excludeHosts?: string[];
  hosts?: string[];
  portListId?: string;
  reverseLookupOnly?: boolean;
  reverseLookupUnify?: boolean;
}

export type NativeTargetCredentialPatchArgs = {
  id: string;
  port?: number;
  host_key_pins?: SshHostKeyPin[];
} | null;

export interface NativeTargetCredentialsPatchArgs {
  esxi?: NativeTargetCredentialPatchArgs;
  krb5?: NativeTargetCredentialPatchArgs;
  smb?: NativeTargetCredentialPatchArgs;
  snmp?: NativeTargetCredentialPatchArgs;
  ssh?: NativeTargetCredentialPatchArgs;
  sshElevate?: NativeTargetCredentialPatchArgs;
}

interface NativeTargetCreateCommonArgs {
  aliveTests: AliveTest[];
  allowSimultaneousIPs: boolean;
  comment?: string;
  credentials?: NativeTargetCredentialsPatchArgs;
  excludeHosts?: string[];
  name: string;
  portListId: string;
  reverseLookupOnly: boolean;
  reverseLookupUnify: boolean;
}

export type NativeTargetCreateArgs = NativeTargetCreateCommonArgs &
  (
    | {hosts: string[]; hostAssetIds?: never}
    | {hosts?: never; hostAssetIds: string[]}
  );

export interface NativeTargetQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
}

export interface NativeTargetsResponse {
  targets: Target[];
  counts: CollectionCounts;
  page: NativeTargetPage;
}

export interface NativeTargetResponse {
  target: Target;
}

const TARGET_SORT_FIELDS: Record<string, string> = {
  created: 'creation_time',
  creation_time: 'creation_time',
  hosts: 'hosts',
  id: 'id',
  ips: 'max_hosts',
  max_hosts: 'max_hosts',
  modified: 'modification_time',
  modification_time: 'modification_time',
  name: 'name',
  port_list: 'port_list',
  task_count: 'task_count',
};

const integerValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const stringValue = (value: unknown, fallback = ''): string =>
  typeof value === 'string' ? value : fallback;

const arrayValue = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string')
    : [];

const nativeSortFromFilter = (filter?: Filter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending, 'name');
  const nativeField = TARGET_SORT_FIELDS[rawField] ?? rawField;
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

export const nativeTargetQueryFromFilter = (
  filter?: Filter,
): NativeTargetQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
  };
};

const yesNoValue = (value?: boolean): 0 | 1 => (value === true ? 1 : 0);

const credentialElement = (item?: NativeCredentialReference) => {
  if (item?.id === undefined || item.id.length === 0) {
    return undefined;
  }
  return {
    _id: item.id,
    name: stringValue(item.name, item.id),
    port: item.port ?? undefined,
    host_key_pins: item.host_key_pins ?? [],
  };
};

const nativeUserTagsElement = (tags: NativeUserTagPayload[]) => ({
  tag: tags.map(tag => ({
    _id: stringValue(tag.id),
    name: stringValue(tag.name),
    value: stringValue(tag.value),
    comment: stringValue(tag.comment),
  })),
});

const targetCommandPermissions = {
  permission: [
    {name: 'get_targets'},
    {name: 'modify_target'},
    {name: 'delete_target'},
  ],
};

export const nativeTargetToModel = (
  item: NativeTargetItem,
  {detail = false}: {detail?: boolean} = {},
): Target => {
  const credentials = item.credentials ?? {};
  const element = {
    _id: stringValue(item.id),
    name: stringValue(item.name),
    comment: stringValue(item.comment),
    permissions: targetCommandPermissions,
    writable: 1,
    in_use: 0,
    hosts: arrayValue(item.hosts).join(','),
    exclude_hosts: arrayValue(item.exclude_hosts).join(','),
    max_hosts: integerValue(item.max_hosts),
    alive_tests: {alive_test: arrayValue(item.alive_tests)},
    allow_simultaneous_ips: yesNoValue(item.allow_simultaneous_ips),
    reverse_lookup_only: yesNoValue(item.reverse_lookup_only),
    reverse_lookup_unify: yesNoValue(item.reverse_lookup_unify),
    port_list: item.port_list
      ? {
          _id: stringValue(item.port_list.id),
          name: stringValue(
            item.port_list.name,
            stringValue(item.port_list.id),
          ),
        }
      : undefined,
    ssh_credential: credentialElement(credentials.ssh),
    ssh_elevate_credential: credentialElement(credentials.ssh_elevate),
    smb_credential: credentialElement(credentials.smb),
    esxi_credential: credentialElement(credentials.esxi),
    snmp_credential: credentialElement(credentials.snmp),
    krb5_credential: credentialElement(credentials.krb5),
    tasks: {
      task: (item.tasks ?? []).map(task => ({
        _id: stringValue(task.id),
        name: stringValue(task.name, stringValue(task.id)),
        usage_type: 'scan',
      })),
    },
    user_tags: detail ? nativeUserTagsElement(item.user_tags ?? []) : undefined,
    creation_time: item.creation_time,
    modification_time: item.modification_time,
  };
  return Target.fromElement(
    element as unknown as Parameters<typeof Target.fromElement>[0],
  );
};

const nativeCounts = (page: NativeTargetPage, length: number) =>
  new CollectionCounts({
    first: page.total > 0 ? (page.page - 1) * page.page_size + 1 : 0,
    all: page.total,
    filtered: page.total,
    length,
    rows: page.page_size,
  });

const nativeHeaders = (gmp: NativeApiGmp): HeadersInit => {
  const headers: HeadersInit = {Accept: 'application/json'};
  if (gmp.session.jwt) {
    headers.Authorization = `Bearer ${gmp.session.jwt}`;
  }
  return headers;
};

const nativeWriteHeaders = (gmp: NativeApiGmp): HeadersInit => ({
  ...nativeHeaders(gmp),
  'Content-Type': 'application/json',
  ...(gmp.session.token ? {'X-YAFVS-Token': gmp.session.token} : {}),
});

const nativeDeleteHeaders = (gmp: NativeApiGmp): HeadersInit => ({
  ...nativeHeaders(gmp),
  ...(gmp.session.token ? {'X-YAFVS-Token': gmp.session.token} : {}),
});

const fetchNativeJson = async <T>(
  gmp: NativeApiGmp,
  path: string,
  params: UrlParams,
): Promise<T> => {
  const response = await fetch(gmp.buildUrl(path, params), {
    credentials: 'include',
    headers: nativeHeaders(gmp),
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
    headers: nativeDeleteHeaders(gmp),
  });
  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }
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
    headers: nativeWriteHeaders(gmp),
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }
  return (await response.json()) as T;
};

export const fetchNativeTargets = async (
  gmp: NativeApiGmp,
  query: NativeTargetQuery,
): Promise<NativeTargetsResponse> => {
  const payload = await fetchNativeJson<NativeTargetCollectionPayload>(
    gmp,
    'api/v1/targets',
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
  const targets = (payload.items ?? []).map(item => nativeTargetToModel(item));
  return {
    targets,
    counts: nativeCounts(page, targets.length),
    page,
  };
};

export const fetchNativeTarget = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<NativeTargetResponse> => {
  const payload = await fetchNativeJson<NativeTargetItem>(
    gmp,
    `api/v1/targets/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return {target: nativeTargetToModel(payload, {detail: true})};
};

export const cloneNativeTarget = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<{id: string}>> => {
  const payload = await writeNativeJson<NativeTargetItem>(
    gmp,
    `api/v1/targets/${encodeURIComponent(id)}/clone`,
    {},
  );
  return new Response({id: stringValue(payload.id)});
};

const nativeTargetCredentialBody = (
  credentials:
    | NativeTargetCreateArgs['credentials']
    | NativeTargetPatchArgs['credentials'],
) =>
  Object.fromEntries(
    Object.entries({
      ssh: credentials?.ssh,
      ssh_elevate: credentials?.sshElevate,
      smb: credentials?.smb,
      esxi: credentials?.esxi,
      snmp: credentials?.snmp,
      krb5: credentials?.krb5,
    }).filter(([, value]) => value !== undefined),
  );

export const nativeTargetCreateBody = (args: NativeTargetCreateArgs) => {
  const credentials = nativeTargetCredentialBody(args.credentials);
  return {
    name: args.name,
    ...(args.comment !== undefined ? {comment: args.comment} : {}),
    port_list_id: args.portListId,
    ...(args.hosts !== undefined ? {hosts: args.hosts} : {}),
    ...(args.hostAssetIds !== undefined
      ? {host_asset_ids: args.hostAssetIds}
      : {}),
    ...(args.excludeHosts !== undefined
      ? {exclude_hosts: args.excludeHosts}
      : {}),
    alive_tests: args.aliveTests,
    allow_simultaneous_ips: args.allowSimultaneousIPs,
    reverse_lookup_only: args.reverseLookupOnly,
    reverse_lookup_unify: args.reverseLookupUnify,
    ...(Object.keys(credentials).length > 0 ? {credentials} : {}),
  };
};

export const nativeTargetPatchBody = ({
  aliveTests,
  allowSimultaneousIPs,
  comment,
  credentials,
  excludeHosts,
  hosts,
  name,
  portListId,
  reverseLookupOnly,
  reverseLookupUnify,
}: NativeTargetPatchArgs) => {
  const credentialBody = nativeTargetCredentialBody(credentials);
  return {
    ...(name !== undefined ? {name} : {}),
    ...(comment !== undefined ? {comment} : {}),
    ...(aliveTests !== undefined ? {alive_tests: aliveTests} : {}),
    ...(allowSimultaneousIPs !== undefined
      ? {allow_simultaneous_ips: allowSimultaneousIPs}
      : {}),
    ...(reverseLookupOnly !== undefined
      ? {reverse_lookup_only: reverseLookupOnly}
      : {}),
    ...(reverseLookupUnify !== undefined
      ? {reverse_lookup_unify: reverseLookupUnify}
      : {}),
    ...(portListId !== undefined ? {port_list_id: portListId} : {}),
    ...(hosts !== undefined ? {hosts} : {}),
    ...(excludeHosts !== undefined ? {exclude_hosts: excludeHosts} : {}),
    ...(Object.keys(credentialBody).length > 0
      ? {credentials: credentialBody}
      : {}),
  };
};

const MAX_NATIVE_TARGET_WRITE_BODY_BYTES = 256 * 1024;

export const nativeTargetWriteBodyFits = (body: unknown) =>
  new TextEncoder().encode(JSON.stringify(body)).byteLength <=
  MAX_NATIVE_TARGET_WRITE_BODY_BYTES;

export const createNativeTarget = async (
  gmp: NativeApiGmp,
  args: NativeTargetCreateArgs,
): Promise<Response<ActionResult>> => {
  const payload = await writeNativeJson<NativeTargetItem>(
    gmp,
    'api/v1/targets',
    nativeTargetCreateBody(args),
  );
  return new Response(
    new ActionResult({
      action_result: {
        action: 'create_target',
        id: stringValue(payload.id),
        message: 'OK',
      },
    }),
  );
};

export const patchNativeTarget = async (
  gmp: NativeApiGmp,
  {
    id,
    aliveTests,
    allowSimultaneousIPs,
    comment,
    credentials,
    excludeHosts,
    hosts,
    name,
    portListId,
    reverseLookupOnly,
    reverseLookupUnify,
  }: NativeTargetPatchArgs,
): Promise<Response<ActionResult>> => {
  const payload = await writeNativeJson<NativeTargetItem>(
    gmp,
    `api/v1/targets/${encodeURIComponent(id)}`,
    nativeTargetPatchBody({
      id,
      aliveTests,
      allowSimultaneousIPs,
      comment,
      credentials,
      excludeHosts,
      hosts,
      name,
      portListId,
      reverseLookupOnly,
      reverseLookupUnify,
    }),
    'PATCH',
  );
  return new Response(
    new ActionResult({
      action_result: {
        action: 'save_target',
        id: stringValue(payload.id),
        message: 'OK',
      },
    }),
  );
};

export const deleteNativeTarget = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<void> =>
  deleteNative(gmp, `api/v1/targets/${encodeURIComponent(id)}`);

export const exportNativeTargetMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativeTargetItem>(
    gmp,
    `api/v1/targets/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};

export const exportNativeTargetsMetadata = async (
  gmp: NativeApiGmp,
  ids: string[],
): Promise<Response<string>> => {
  const targets = await Promise.all(
    ids.map(async id => {
      const payload = await fetchNativeJson<NativeTargetItem>(
        gmp,
        `api/v1/targets/${encodeURIComponent(id)}/export`,
        {token: gmp.session.token},
      );
      return payload;
    }),
  );
  return new Response(`${JSON.stringify({targets}, null, 2)}\n`);
};
