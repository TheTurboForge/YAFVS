/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import type {UrlParams} from 'gmp/http/utils';
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
}

export interface NativeTasksResponse {
  tasks: Task[];
  counts: CollectionCounts;
  page: NativeTaskPage;
}

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
