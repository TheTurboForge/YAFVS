/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import type {UrlParams} from 'gmp/http/utils';
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
