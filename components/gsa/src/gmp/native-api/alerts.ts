/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import Response from 'gmp/http/response';
import type {UrlParams} from 'gmp/http/utils';
import ActionResult from 'gmp/models/action-result';
import Alert from 'gmp/models/alert';
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

interface NativeAlertReferencePayload {
  id?: string;
  name?: string;
}

interface NativeAlertTypeLabelPayload {
  type?: string;
}

interface NativeAlertPayload {
  id?: string;
  name?: string;
  comment?: string;
  owner?: {name?: string};
  active?: boolean;
  in_use?: boolean;
  task_count?: number;
  event?: NativeAlertTypeLabelPayload;
  condition?: NativeAlertTypeLabelPayload;
  method?: NativeAlertTypeLabelPayload;
  method_data_redacted?: boolean;
  filter?: NativeAlertReferencePayload;
  tasks?: NativeAlertReferencePayload[];
  created_at?: string;
  modified_at?: string;
}

interface NativeAlertsPayload {
  page?: Partial<NativePage>;
  items?: NativeAlertPayload[];
}

export interface NativeAlertsQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
}

export interface NativeAlertsResponse {
  alerts: Alert[];
  counts: CollectionCounts;
  page: NativePage;
}

export interface NativeAlertPatchArgs {
  id: string;
  name?: string;
  comment?: string;
}

export interface NativeAlertCloneArgs {
  name?: string;
  comment?: string;
}

export type NativeAlertMethod =
  | 'EMAIL'
  | 'SMB'
  | 'SYSLOG'
  | 'SNMP'
  | 'SCP'
  | 'START_TASK';

export interface NativeAlertCreateArgs {
  method: NativeAlertMethod;
  [key: string]: unknown;
}

export interface NativeAlertDefinitionPayload {
  revision: string;
  method: NativeAlertMethod;
  name?: string;
  comment?: string;
  active?: boolean;
  status?: string;
  snmp_community_configured?: boolean;
  [key: string]: unknown;
}

export interface NativeAlertDefinitionPutArgs {
  method: NativeAlertMethod;
  snmp_community_mode?: 'preserve' | 'replace';
  snmp_community?: string;
  [key: string]: unknown;
}

interface NativeApiErrorPayload {
  error?: {
    code?: unknown;
    message?: unknown;
  };
}

class NativeAlertRequestError extends Error {
  readonly code?: string;

  constructor(status: number, code?: string, message?: string) {
    super(
      [`Native API request failed with status ${status}`, code, message]
        .filter(value => value !== undefined && value !== '')
        .join(': '),
    );
    this.name = 'NativeAlertRequestError';
    this.code = code;
  }
}

const ALERT_SORT_FIELDS: Record<string, string> = {
  active: 'active',
  condition: 'condition',
  created: 'created',
  event: 'event',
  filter: 'filter',
  id: 'id',
  method: 'method',
  modified: 'modified',
  name: 'name',
  task_count: 'task_count',
  tasks: 'tasks',
};

const stringValue = (value: unknown, fallback = ''): string =>
  typeof value === 'string' ? value : fallback;

const integerValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const errorString = (value: unknown): string | undefined =>
  typeof value === 'string' && value !== '' ? value : undefined;

const nativeAlertRequestError = async (response: globalThis.Response) => {
  let payload: NativeApiErrorPayload | undefined;
  try {
    payload = (await response.json()) as NativeApiErrorPayload;
  } catch {
    // Errors may not have a JSON body; retain only the status in that case.
  }

  return new NativeAlertRequestError(
    response.status,
    errorString(payload?.error?.code),
    errorString(payload?.error?.message),
  );
};

const yesNoValue = (value?: boolean): 0 | 1 => (value === true ? 1 : 0);

const nativeSortFromFilter = (filter?: QueryFilter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending, 'name');
  const nativeField = ALERT_SORT_FIELDS[rawField] ?? rawField;
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

export const nativeAlertsQueryFromFilter = (
  filter?: QueryFilter,
): NativeAlertsQuery => {
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

const nativeAlertDefinitionData = (name: string, value: unknown) =>
  value === undefined
    ? []
    : [
        {
          name,
          __text:
            typeof value === 'string' || typeof value === 'number'
              ? value
              : value === true
                ? '1'
                : value === false
                  ? '0'
                  : '',
        },
      ];

const nativeAlertDefinitionMethodType = (method: NativeAlertMethod) => {
  switch (method) {
    case 'EMAIL':
      return 'Email';
    case 'SYSLOG':
      return 'Syslog';
    case 'START_TASK':
      return 'Start Task';
    default:
      return method;
  }
};

const nativeAlertDefinitionToModel = (
  id: string,
  definition: NativeAlertDefinitionPayload,
): Alert => {
  const methodData: Array<{
    name: string;
    __text?: string | number;
    credential?: {_id: string};
  }> = [
    ...nativeAlertDefinitionData('to_address', definition.to_address),
    ...nativeAlertDefinitionData('from_address', definition.from_address),
    ...nativeAlertDefinitionData('subject', definition.subject),
    ...nativeAlertDefinitionData(
      'recipient_credential',
      definition.recipient_credential_id,
    ),
    ...nativeAlertDefinitionData('message', definition.message),
    ...nativeAlertDefinitionData('snmp_agent', definition.snmp_agent),
    ...nativeAlertDefinitionData(
      'snmp_community_configured',
      definition.snmp_community_configured,
    ),
    ...nativeAlertDefinitionData('snmp_message', definition.snmp_message),
    ...nativeAlertDefinitionData('scp_host', definition.scp_host),
    ...nativeAlertDefinitionData('scp_port', definition.scp_port),
    ...nativeAlertDefinitionData('scp_known_hosts', definition.scp_known_hosts),
    ...nativeAlertDefinitionData('scp_path', definition.scp_path),
    ...nativeAlertDefinitionData('smb_share_path', definition.smb_share_path),
    ...nativeAlertDefinitionData('smb_file_path', definition.smb_file_path),
    ...nativeAlertDefinitionData(
      'smb_max_protocol',
      definition.smb_max_protocol,
    ),
    ...nativeAlertDefinitionData('start_task_task', definition.task_id),
  ];

  if (definition.method === 'EMAIL') {
    const notice = definition.notice;
    methodData.push(
      ...nativeAlertDefinitionData(
        'notice',
        notice === 'simple'
          ? '1'
          : notice === 'include'
            ? '0'
            : notice === 'attach'
              ? '2'
              : notice,
      ),
      ...nativeAlertDefinitionData(
        notice === 'attach' ? 'notice_attach_format' : 'notice_report_format',
        definition.report_format_id,
      ),
    );
  }

  if (definition.method === 'SCP') {
    methodData.push(
      ...nativeAlertDefinitionData(
        'scp_report_format',
        definition.report_format_id,
      ),
      ...(definition.scp_credential_id === undefined
        ? []
        : [
            {
              name: 'scp_credential',
              credential: {_id: String(definition.scp_credential_id)},
            },
          ]),
    );
  }

  if (definition.method === 'SMB') {
    methodData.push(
      ...nativeAlertDefinitionData(
        'smb_credential',
        definition.smb_credential_id,
      ),
      ...nativeAlertDefinitionData(
        'smb_report_format',
        definition.report_format_id,
      ),
    );
  }

  const model = Alert.fromElement({
    _id: id,
    name: stringValue(definition.name),
    comment: stringValue(definition.comment),
    active: yesNoValue(definition.active),
    writable: 1,
    permissions: {
      permission: [
        {name: 'get_alerts'},
        {name: 'create_alert'},
        {name: 'modify_alert'},
        {name: 'delete_alert'},
        {name: 'test_alert'},
      ],
    },
    event: {
      __text: 'Task run status changed',
      data: nativeAlertDefinitionData('status', definition.status),
    },
    condition: {__text: 'Always'},
    method: {
      __text: nativeAlertDefinitionMethodType(definition.method),
      data: methodData,
    },
    tasks: {task: []},
  });
  return Object.assign(model, {definitionRevision: definition.revision});
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
    throw await nativeAlertRequestError(response);
  }

  return (await response.json()) as T;
};

export const fetchNativeAlertDefinitionPayload = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<NativeAlertDefinitionPayload> =>
  await fetchNativeJson<NativeAlertDefinitionPayload>(
    gmp,
    `api/v1/alerts/${encodeURIComponent(id)}/definition`,
    {token: gmp.session.token},
  );

export const fetchNativeAlertDefinition = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Alert> =>
  nativeAlertDefinitionToModel(
    id,
    await fetchNativeAlertDefinitionPayload(gmp, id),
  );

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
    throw await nativeAlertRequestError(response);
  }
};

export const replaceNativeAlertDefinition = async (
  gmp: NativeApiGmp,
  id: string,
  expectedRevision: string,
  definition: NativeAlertDefinitionPutArgs,
): Promise<Response<ActionResult>> => {
  await writeNativeJson<NativeAlertDefinitionPayload>(
    gmp,
    `api/v1/alerts/${encodeURIComponent(id)}/definition`,
    {expected_revision: expectedRevision, definition},
    'PUT',
  );
  return new Response(
    new ActionResult({
      action_result: {action: 'save_alert', id, message: 'OK'},
    }),
  );
};

export const deliverNativeAlertReport = async (
  gmp: NativeApiGmp,
  alertId: string,
  reportId: string,
  filter: string,
): Promise<Response<unknown>> => {
  const response = await fetch(
    gmp.buildUrl(`api/v1/alerts/${encodeURIComponent(alertId)}/deliver-report`),
    {
      method: 'POST',
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        ...(gmp.session.token ? {'X-YAFVS-Token': gmp.session.token} : {}),
        ...(gmp.session.jwt
          ? {Authorization: `Bearer ${gmp.session.jwt}`}
          : {}),
      },
      body: JSON.stringify({report_id: reportId, filter}),
    },
  );

  if (!response.ok) {
    throw await nativeAlertRequestError(response);
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    // Successful report delivery may not include a response body.
  }
  return new Response(payload);
};

const writeNativeJson = async <T>(
  gmp: NativeApiGmp,
  path: string,
  body: unknown,
  method = 'PATCH',
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
    throw await nativeAlertRequestError(response);
  }

  return (await response.json()) as T;
};

const nativeTypeElement = (label?: NativeAlertTypeLabelPayload) => ({
  __text: stringValue(label?.type),
});

const nativeReferenceElement = (reference?: NativeAlertReferencePayload) =>
  reference?.id === undefined
    ? undefined
    : {
        _id: stringValue(reference.id),
        name: stringValue(reference.name, stringValue(reference.id)),
      };

const nativeTaskElements = (tasks?: NativeAlertReferencePayload[]) => ({
  task: (tasks ?? [])
    .filter(task => task.id !== undefined)
    .map(task => ({
      _id: stringValue(task.id),
      name: stringValue(task.name, stringValue(task.id)),
      usage_type: 'scan' as const,
    })),
});

const nativeAlertToModel = (item: NativeAlertPayload): Alert =>
  Alert.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name),
    comment: stringValue(item.comment),
    owner: {name: stringValue(item.owner?.name)},
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    active: yesNoValue(item.active),
    in_use: yesNoValue(item.in_use),
    writable: 1,
    permissions: {
      permission: [
        {name: 'get_alerts'},
        {name: 'create_alert'},
        {name: 'modify_alert'},
        {name: 'delete_alert'},
        {name: 'test_alert'},
      ],
    },
    event: nativeTypeElement(item.event),
    condition: nativeTypeElement(item.condition),
    method: nativeTypeElement(item.method),
    filter: nativeReferenceElement(item.filter),
    tasks: nativeTaskElements(item.tasks),
  });

const normalizePage = (
  payloadPage: Partial<NativePage> | undefined,
  query: NativeAlertsQuery,
): NativePage => ({
  page: payloadPage?.page ?? query.page,
  page_size: payloadPage?.page_size ?? query.pageSize,
  total: payloadPage?.total ?? 0,
  sort: payloadPage?.sort ?? query.sort,
  filter: payloadPage?.filter ?? query.filter,
});

export const fetchNativeAlerts = async (
  gmp: NativeApiGmp,
  query: NativeAlertsQuery,
): Promise<NativeAlertsResponse> => {
  const payload = await fetchNativeJson<NativeAlertsPayload>(
    gmp,
    'api/v1/alerts',
    {
      token: gmp.session.token,
      page: query.page,
      page_size: query.pageSize,
      sort: query.sort,
      filter: query.filter,
    },
  );
  const page = normalizePage(payload.page, query);
  const alerts = (payload.items ?? []).map(nativeAlertToModel);
  return {
    alerts,
    counts: nativeCounts(page, alerts.length),
    page,
  };
};

export const fetchNativeAlert = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Alert> => {
  const payload = await fetchNativeJson<NativeAlertPayload>(
    gmp,
    `api/v1/alerts/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return nativeAlertToModel(payload);
};

export const exportNativeAlertMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativeAlertPayload>(
    gmp,
    `api/v1/alerts/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};

export const exportNativeAlertsMetadata = async (
  gmp: NativeApiGmp,
  ids: string[],
): Promise<Response<string>> => {
  const alerts = await Promise.all(
    ids.map(async id => {
      const payload = await fetchNativeJson<NativeAlertPayload>(
        gmp,
        `api/v1/alerts/${encodeURIComponent(id)}/export`,
        {token: gmp.session.token},
      );
      return payload;
    }),
  );
  return new Response(`${JSON.stringify({alerts}, null, 2)}\n`);
};

export const patchNativeAlert = async (
  gmp: NativeApiGmp,
  {id, name, comment}: NativeAlertPatchArgs,
): Promise<Response<ActionResult>> => {
  const body = {
    ...(name !== undefined ? {name} : {}),
    ...(comment !== undefined ? {comment} : {}),
  };
  const payload = await writeNativeJson<NativeAlertPayload>(
    gmp,
    `api/v1/alerts/${encodeURIComponent(id)}`,
    body,
  );
  return new Response(
    new ActionResult({
      action_result: {
        action: 'save_alert',
        id: stringValue(payload.id),
        message: 'OK',
      },
    }),
  );
};

export const cloneNativeAlert = async (
  gmp: NativeApiGmp,
  id: string,
  request: NativeAlertCloneArgs = {},
): Promise<Response<{id: string}>> => {
  const payload = await writeNativeJson<NativeAlertPayload>(
    gmp,
    `api/v1/alerts/${encodeURIComponent(id)}/clone`,
    request,
    'POST',
  );
  return new Response({id: stringValue(payload.id)});
};

export const createNativeAlert = async (
  gmp: NativeApiGmp,
  request: NativeAlertCreateArgs,
): Promise<Response<{id: string}>> => {
  const payload = await writeNativeJson<NativeAlertPayload>(
    gmp,
    'api/v1/alerts',
    request,
    'POST',
  );
  return new Response({id: stringValue(payload.id)});
};

export const deleteNativeAlert = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<void> =>
  deleteNative(gmp, `api/v1/alerts/${encodeURIComponent(id)}`);

export const testNativeAlert = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<void> => {
  const response = await fetch(
    gmp.buildUrl(`api/v1/alerts/${encodeURIComponent(id)}/test`),
    {
      method: 'POST',
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
    throw await nativeAlertRequestError(response);
  }
};
