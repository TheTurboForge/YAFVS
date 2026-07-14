/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import Response from 'gmp/http/response';
import type {UrlParams} from 'gmp/http/utils';
import ActionResult from 'gmp/models/action-result';
import type Filter from 'gmp/models/filter';
import Task from 'gmp/models/task';

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

interface NativeTaskReportReference {
  id?: string;
  timestamp?: string;
  scan_start?: string;
  scan_end?: string;
  severity?: number;
}

interface NativeTaskReportCount {
  total?: number;
  finished?: number;
}

interface NativeTaskItem {
  id?: string;
  name?: string;
  comment?: string;
  status?: string;
  progress?: number;
  trend?: string;
  usage_type?: string;
  target?: NativeReference;
  config?: NativeReference;
  scanner?: NativeReference;
  scanner_type?: number | string | null;
  schedule?: NativeReference;
  start_time?: string | null;
  end_time?: string | null;
  schedule_next_time?: string | null;
  schedule_periods?: number | null;
  alerts?: NativeReference[];
  apply_overrides?: boolean;
  auto_delete_data?: number;
  max_checks?: number;
  max_hosts?: number;
  min_qod?: number;
  hosts_ordering?: 'random' | 'sequential' | 'reverse';
  alterable?: boolean | null;
  report_count?: NativeTaskReportCount;
  current_report?: NativeTaskReportReference;
  last_report?: NativeTaskReportReference;
  max_severity?: number;
  creation_time?: string;
  modification_time?: string;
}

interface NativeTaskPage {
  page: number;
  page_size: number;
  total: number;
  sort: string;
  filter: string;
}

interface NativeTaskCollectionPayload {
  page?: Partial<NativeTaskPage>;
  items?: NativeTaskItem[];
}

export interface NativeTaskQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
  schedulesOnly?: boolean;
}

export interface NativeTasksResponse {
  tasks: Task[];
  counts: CollectionCounts;
  page: NativeTaskPage;
}

export interface NativeTaskResponse {
  task: Task;
}

interface NativeTaskPatchArgs {
  id: string;
  name?: string;
  comment?: string;
}

export interface NativeTaskWriteArgs {
  name: string;
  comment?: string;
  targetId: string;
  configId: string;
  scannerId: string;
  scheduleId?: string;
  schedulePeriods: number;
  alertIds: string[];
  applyOverrides: boolean;
  maxChecks: number;
  maxHosts: number;
  minQod: number;
  hostsOrdering?: 'random' | 'sequential' | 'reverse';
  tagId?: string;
}

interface NativeTaskStopPayload {
  task_id?: unknown;
  status?: unknown;
}

interface NativeApiErrorPayload {
  error?: {
    code?: unknown;
    message?: unknown;
  };
}

class NativeTaskRequestError extends Error {
  readonly code?: string;

  constructor(status: number, code?: string, message?: string) {
    super(
      [`Native API request failed with status ${status}`, code, message]
        .filter(value => value !== undefined && value !== '')
        .join(': '),
    );
    this.name = 'NativeTaskRequestError';
    this.code = code;
  }
}

export const isNativeTaskMutationOutcomeUncertain = (
  error: unknown,
): boolean => {
  const code = (error as {code?: unknown} | undefined)?.code;
  return (
    code === 'committed_response_unavailable' ||
    code === 'mutation_outcome_indeterminate'
  );
};

const TASK_SORT_FIELDS: Record<string, string> = {
  config: 'config',
  created: 'creation_time',
  creation_time: 'creation_time',
  id: 'id',
  last: 'last_report',
  last_report: 'last_report',
  modified: 'modification_time',
  modification_time: 'modification_time',
  name: 'name',
  scanner: 'scanner',
  schedule: 'schedule',
  severity: 'max_severity',
  status: 'status',
  target: 'target',
  total: 'report_count',
  trend: 'trend',
};

const integerValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const numberValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseFloat(String(value ?? fallback));
  return Number.isFinite(parsed) ? parsed : fallback;
};

const stringValue = (value: unknown, fallback = ''): string =>
  typeof value === 'string' ? value : fallback;

const errorString = (value: unknown): string | undefined =>
  typeof value === 'string' && value !== '' ? value : undefined;

const nativeTaskRequestError = async (response: globalThis.Response) => {
  let payload: NativeApiErrorPayload | undefined;
  try {
    payload = (await response.json()) as NativeApiErrorPayload;
  } catch {
    // Errors may not have a JSON body; retain only the status in that case.
  }

  return new NativeTaskRequestError(
    response.status,
    errorString(payload?.error?.code),
    errorString(payload?.error?.message),
  );
};

const nativeSortFromFilter = (filter?: Filter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending, 'name');
  const nativeField = TASK_SORT_FIELDS[rawField] ?? rawField;
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

export const nativeTaskQueryFromFilter = (filter?: Filter): NativeTaskQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
  };
};

const referenceElement = (item?: NativeReference, entityType?: string) => {
  if (item?.id === undefined || item.id.length === 0) {
    return undefined;
  }
  return {
    _id: item.id,
    name: stringValue(item.name, item.id),
    _type: entityType,
  };
};

const reportElement = (report?: NativeTaskReportReference) => {
  if (report?.id === undefined || report.id.length === 0) {
    return undefined;
  }
  return {
    report: {
      _id: report.id,
      timestamp: report.timestamp,
      scan_start: report.scan_start,
      scan_end: report.scan_end,
      severity: numberValue(report.severity),
    },
  };
};

const taskCommandPermissions = {
  permission: [
    {name: 'get_tasks'},
    {name: 'modify_task'},
    {name: 'delete_task'},
    {name: 'start_task'},
    {name: 'stop_task'},
    {name: 'export_task'},
  ],
};

export const nativeTaskToModel = (item: NativeTaskItem): Task => {
  const reportCount = item.report_count ?? {};
  const scanner = referenceElement(item.scanner, 'scanner') as
    | Record<string, unknown>
    | undefined;
  if (scanner !== undefined && item.scanner_type !== undefined) {
    scanner.type = item.scanner_type;
  }
  const element = {
    _id: stringValue(item.id),
    name: stringValue(item.name),
    comment: stringValue(item.comment),
    permissions: taskCommandPermissions,
    writable: 1,
    in_use: 0,
    status: stringValue(item.status, 'Unknown'),
    progress: integerValue(item.progress),
    trend: stringValue(item.trend),
    usage_type: stringValue(item.usage_type, 'scan'),
    target: referenceElement(item.target, 'target'),
    config: referenceElement(item.config, 'scanconfig'),
    scanner,
    schedule: referenceElement(item.schedule, 'schedule'),
    hosts_ordering: item.hosts_ordering,
    alert: (item.alerts ?? []).flatMap(alert => {
      const reference = referenceElement(alert, 'alert');
      return reference === undefined ? [] : [reference];
    }),
    preferences: {
      preference: [
        {
          scanner_name: 'assets_apply_overrides',
          value: item.apply_overrides === false ? 'no' : 'yes',
        },
        {
          scanner_name: 'assets_min_qod',
          value: String(integerValue(item.min_qod, 70)),
        },
        {
          scanner_name: 'auto_delete',
          value: 'keep',
        },
        {
          scanner_name: 'auto_delete_data',
          value: String(integerValue(item.auto_delete_data, 10)),
        },
        {
          scanner_name: 'max_checks',
          value: String(integerValue(item.max_checks, 4)),
        },
        {
          scanner_name: 'max_hosts',
          value: String(integerValue(item.max_hosts, 20)),
        },
      ],
    },
    alterable:
      item.alterable === undefined || item.alterable === null
        ? undefined
        : item.alterable
          ? 1
          : 0,
    schedule_periods: item.schedule_periods ?? undefined,
    report_count: {
      __text: integerValue(reportCount.total),
      finished: integerValue(reportCount.finished),
    },
    current_report: reportElement(item.current_report),
    last_report: reportElement(item.last_report),
    creation_time: item.creation_time,
    modification_time: item.modification_time,
  };
  return Task.fromElement(
    element as unknown as Parameters<typeof Task.fromElement>[0],
  );
};

const nativeCounts = (page: NativeTaskPage, length: number) =>
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
    headers: {
      Accept: 'application/json',
      'X-TurboVAS-Token': gmp.session.token ?? '',
      ...(gmp.session.jwt ? {Authorization: `Bearer ${gmp.session.jwt}`} : {}),
    },
  });

  if (!response.ok) {
    throw await nativeTaskRequestError(response);
  }
};

const writeNativeJson = async <T>(
  gmp: NativeApiGmp,
  path: string,
  body?: unknown,
  method = 'POST',
): Promise<T> => {
  const headers: HeadersInit = {
    Accept: 'application/json',
    ...(body !== undefined ? {'Content-Type': 'application/json'} : {}),
    ...(gmp.session.token ? {'X-TurboVAS-Token': gmp.session.token} : {}),
    ...(gmp.session.jwt ? {Authorization: `Bearer ${gmp.session.jwt}`} : {}),
  };
  const response = await fetch(gmp.buildUrl(path), {
    method,
    credentials: 'include',
    headers,
    ...(body !== undefined ? {body: JSON.stringify(body)} : {}),
  });

  if (!response.ok) {
    throw await nativeTaskRequestError(response);
  }

  return (await response.json()) as T;
};

export const fetchNativeTasks = async (
  gmp: NativeApiGmp,
  query: NativeTaskQuery,
): Promise<NativeTasksResponse> => {
  const payload = await fetchNativeJson<NativeTaskCollectionPayload>(
    gmp,
    'api/v1/tasks',
    {
      token: gmp.session.token,
      page: query.page,
      page_size: query.pageSize,
      sort: query.sort,
      filter: query.filter,
      ...(query.schedulesOnly ? {schedules_only: 'true'} : {}),
    },
  );
  const page = {
    page: integerValue(payload.page?.page, 1),
    page_size: integerValue(payload.page?.page_size, query.pageSize),
    total: integerValue(payload.page?.total),
    sort: stringValue(payload.page?.sort),
    filter: stringValue(payload.page?.filter),
  };
  const tasks = (payload.items ?? []).map(nativeTaskToModel);
  return {
    tasks,
    counts: nativeCounts(page, tasks.length),
    page,
  };
};

export const fetchNativeTask = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<NativeTaskResponse> => {
  const payload = await fetchNativeJson<NativeTaskItem>(
    gmp,
    `api/v1/tasks/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return {task: nativeTaskToModel(payload)};
};

export const exportNativeTaskMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativeTaskItem>(
    gmp,
    `api/v1/tasks/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};

export const exportNativeTasksMetadata = async (
  gmp: NativeApiGmp,
  ids: string[],
): Promise<Response<string>> => {
  const tasks = await Promise.all(
    ids.map(async id => {
      const payload = await fetchNativeJson<NativeTaskItem>(
        gmp,
        `api/v1/tasks/${encodeURIComponent(id)}/export`,
        {token: gmp.session.token},
      );
      return payload;
    }),
  );
  return new Response(`${JSON.stringify({tasks}, null, 2)}\n`);
};

export const patchNativeTask = async (
  gmp: NativeApiGmp,
  {id, name, comment}: NativeTaskPatchArgs,
): Promise<Response<ActionResult>> => {
  const body = {
    ...(name !== undefined ? {name} : {}),
    ...(comment !== undefined ? {comment} : {}),
  };
  const payload = await writeNativeJson<NativeTaskItem>(
    gmp,
    `api/v1/tasks/${encodeURIComponent(id)}`,
    body,
    'PATCH',
  );
  return new Response(
    new ActionResult({
      action_result: {
        action: 'save_task',
        id: stringValue(payload.id),
        message: 'OK',
      },
    }),
  );
};

const nativeTaskWriteBody = (args: NativeTaskWriteArgs) => ({
  name: args.name,
  ...(args.comment !== undefined ? {comment: args.comment} : {}),
  target_id: args.targetId,
  config_id: args.configId,
  scanner_id: args.scannerId,
  schedule_id: args.scheduleId ?? null,
  schedule_periods: args.schedulePeriods,
  alert_ids: args.alertIds,
  hosts_ordering: args.hostsOrdering ?? 'random',
  apply_overrides: args.applyOverrides,
  max_checks: args.maxChecks,
  max_hosts: args.maxHosts,
  min_qod: args.minQod,
});

export const createNativeTask = async (
  gmp: NativeApiGmp,
  args: NativeTaskWriteArgs,
): Promise<Response<ActionResult>> => {
  const payload = await writeNativeJson<NativeTaskItem>(gmp, 'api/v1/tasks', {
    ...nativeTaskWriteBody(args),
    ...(args.tagId !== undefined ? {tag_id: args.tagId} : {}),
  });
  return new Response(
    new ActionResult({
      action_result: {
        action: 'create_task',
        id: stringValue(payload.id),
        message: 'OK',
      },
    }),
  );
};

export const replaceNativeTaskConfiguration = async (
  gmp: NativeApiGmp,
  id: string,
  args: NativeTaskWriteArgs,
): Promise<Response<ActionResult>> => {
  const payload = await writeNativeJson<NativeTaskItem>(
    gmp,
    `api/v1/tasks/${encodeURIComponent(id)}/replace-configuration`,
    nativeTaskWriteBody(args),
  );
  return new Response(
    new ActionResult({
      action_result: {
        action: 'save_task',
        id: stringValue(payload.id),
        message: 'OK',
      },
    }),
  );
};

export const cloneNativeTask = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<{id: string}>> => {
  const payload = await writeNativeJson<NativeTaskItem>(
    gmp,
    `api/v1/tasks/${encodeURIComponent(id)}/clone`,
  );
  return new Response({id: stringValue(payload.id)});
};

export const startNativeTask = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<void> => {
  await writeNativeJson(
    gmp,
    `api/v1/tasks/${encodeURIComponent(id)}/start`,
    {},
  );
};

export const stopNativeTask = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<void> => {
  const payload = await writeNativeJson<NativeTaskStopPayload>(
    gmp,
    `api/v1/tasks/${encodeURIComponent(id)}/stop`,
    {},
  );
  if (payload.task_id !== id || payload.status !== 'stopped') {
    throw new Error('Native API returned an invalid task stop response');
  }
};

export const deleteNativeTask = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<void> => deleteNative(gmp, `api/v1/tasks/${encodeURIComponent(id)}`);
