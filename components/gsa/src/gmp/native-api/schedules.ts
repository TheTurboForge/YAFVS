/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import Response from 'gmp/http/response';
import type {UrlParams} from 'gmp/http/utils';
import Schedule from 'gmp/models/schedule';
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

interface NativeScheduleTaskPayload {
  id: string;
  name: string;
  usage_type?: string;
}

interface NativeUserTagPayload {
  id: string;
  name: string;
  value: string;
  comment: string;
}

interface NativeSchedulePayload {
  id: string;
  name: string;
  comment?: string;
  icalendar?: string;
  timezone?: string;
  timezone_abbrev?: string;
  tasks?: NativeScheduleTaskPayload[];
  user_tags?: NativeUserTagPayload[];
  created_at?: string;
  modified_at?: string;
}

interface NativeSchedulesPayload {
  page?: Partial<NativePage>;
  items?: NativeSchedulePayload[];
}

interface NativeSchedulePatchArgs {
  id: string;
  name?: string;
  comment?: string;
}

export interface NativeSchedulesQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
}

export interface NativeSchedulesResponse {
  schedules: Schedule[];
  counts: CollectionCounts;
  page: NativePage;
}

const SCHEDULE_SORT_FIELDS: Record<string, string> = {
  name: 'name',
  first_run: 'first_run',
  next_run: 'next_run',
  period: 'period',
  duration: 'duration',
  tasks: 'tasks',
  created: 'created',
  modified: 'modified',
};

const stringValue = (value: unknown, fallback = ''): string =>
  typeof value === 'string' && value.length > 0 ? value : fallback;

const integerValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const nativeSortFromFilter = (filter?: QueryFilter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending, 'name');
  const nativeField = SCHEDULE_SORT_FIELDS[rawField] ?? rawField;
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

export const nativeSchedulesQueryFromFilter = (
  filter?: QueryFilter,
): NativeSchedulesQuery => {
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

const nativeUserTagsElement = (tags: NativeUserTagPayload[] = []) => ({
  tag: tags.map(tag => ({
    _id: stringValue(tag.id),
    name: stringValue(tag.name),
    value: stringValue(tag.value),
    comment: stringValue(tag.comment),
  })),
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
      ...(gmp.session.token ? {'X-TurboVAS-Token': gmp.session.token} : {}),
      ...(gmp.session.jwt ? {Authorization: `Bearer ${gmp.session.jwt}`} : {}),
    },
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
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...(gmp.session.token ? {'X-TurboVAS-Token': gmp.session.token} : {}),
      ...(gmp.session.jwt ? {Authorization: `Bearer ${gmp.session.jwt}`} : {}),
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }

  return (await response.json()) as T;
};

const nativeScheduleToModel = (
  item: NativeSchedulePayload,
  {detail = false}: {detail?: boolean} = {},
): Schedule =>
  Schedule.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name),
    comment: stringValue(item.comment),
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    writable: 1,
    permissions: {permission: [{name: 'everything'}]},
    icalendar: stringValue(item.icalendar),
    timezone: stringValue(item.timezone, 'UTC'),
    timezone_abbrev: stringValue(item.timezone_abbrev),
    tasks: {
      task: (item.tasks ?? []).map(task => ({
        _id: stringValue(task.id),
        name: stringValue(task.name),
        usage_type: 'scan' as const,
      })),
    },
    user_tags: detail ? nativeUserTagsElement(item.user_tags ?? []) : undefined,
  });

export const fetchNativeSchedules = async (
  gmp: NativeApiGmp,
  query: NativeSchedulesQuery,
): Promise<NativeSchedulesResponse> => {
  const payload = await fetchNativeJson<NativeSchedulesPayload>(
    gmp,
    'api/v1/schedules',
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
  const schedules = (payload.items ?? []).map(item =>
    nativeScheduleToModel(item),
  );
  return {
    schedules,
    counts: nativeCounts(page, schedules.length),
    page,
  };
};

export const fetchNativeSchedule = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Schedule> => {
  const payload = await fetchNativeJson<NativeSchedulePayload>(
    gmp,
    `api/v1/schedules/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return nativeScheduleToModel(payload, {detail: true});
};

export const exportNativeScheduleMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativeSchedulePayload>(
    gmp,
    `api/v1/schedules/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};

export const exportNativeSchedulesMetadata = async (
  gmp: NativeApiGmp,
  ids: string[],
): Promise<Response<string>> => {
  const schedules = await Promise.all(
    ids.map(id =>
      fetchNativeJson<NativeSchedulePayload>(
        gmp,
        `api/v1/schedules/${encodeURIComponent(id)}/export`,
        {token: gmp.session.token},
      ),
    ),
  );
  return new Response(`${JSON.stringify({schedules}, null, 2)}\n`);
};

export const cloneNativeSchedule = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<{id: string}>> => {
  const payload = await writeNativeJson<NativeSchedulePayload>(
    gmp,
    `api/v1/schedules/${encodeURIComponent(id)}/clone`,
    {},
  );
  return new Response({id: stringValue(payload.id)});
};

export const deleteNativeSchedule = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<void> =>
  deleteNative(gmp, `api/v1/schedules/${encodeURIComponent(id)}`);

export const patchNativeSchedule = async (
  gmp: NativeApiGmp,
  {id, name, comment}: NativeSchedulePatchArgs,
): Promise<Response<{id: string}>> => {
  const body = {
    ...(name !== undefined ? {name} : {}),
    ...(comment !== undefined ? {comment} : {}),
  };
  const payload = await writeNativeJson<NativeSchedulePayload>(
    gmp,
    `api/v1/schedules/${encodeURIComponent(id)}`,
    body,
    'PATCH',
  );
  return new Response({id: stringValue(payload.id)});
};
