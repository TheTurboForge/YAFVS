/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import {
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import Response from 'gmp/http/response';
import type Http from 'gmp/http/http';
import type {UrlParams} from 'gmp/http/utils';
import Schedule from 'gmp/models/schedule';
import type Filter from 'gmp/models/filter';
import {filterString} from 'gmp/models/filter/utils';

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
  icalendar?: string;
  timezone?: string;
}

export interface NativeScheduleCreateArgs {
  name: string;
  comment?: string;
  timezone?: string;
  icalendar: string;
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

interface ScheduleCommandParams {
  id: string;
  filter?: Filter | string;
  [key: string]: unknown;
}

interface ScheduleCommandOptions {
  filter?: Filter | string;
  [key: string]: unknown;
}

interface SchedulesCommandParams {
  filter?: Filter | string;
  [key: string]: unknown;
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

const nativeSortFromFilter = (filter?: Filter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending, 'name');
  const nativeField = SCHEDULE_SORT_FIELDS[rawField] ?? rawField;
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

export const nativeSchedulesQueryFromFilter = (
  filter?: Filter,
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
      ...(gmp.session.token ? {'X-YAFVS-Token': gmp.session.token} : {}),
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

const shouldApplyToAllFilteredSchedules = (filter: Filter) => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

const scheduleIds = (schedules: Schedule[]) =>
  schedules.flatMap(schedule =>
    schedule.id === undefined ? [] : [schedule.id],
  );

const nativeScheduleDetailSupportsFilter = (filter?: Filter | string) => {
  const value = filterString(filter);
  return filter === undefined || value === 'tasks=1' || value === 'alerts=1';
};

export class NativeScheduleBulkDeleteError extends Error {
  readonly deletedIds: string[];
  readonly failedId: string;
  readonly pendingIds: string[];

  constructor(
    deletedIds: string[],
    failedId: string,
    pendingIds: string[],
    cause: unknown,
  ) {
    super(
      `Native schedule bulk delete stopped at ${failedId} after deleting ${deletedIds.length} schedule(s).`,
      {cause},
    );
    this.name = 'NativeScheduleBulkDeleteError';
    this.deletedIds = deletedIds;
    this.failedId = failedId;
    this.pendingIds = pendingIds;
  }
}

export class ScheduleCommand {
  private readonly http: Http;

  constructor(http: Http) {
    this.http = http;
  }

  async get(
    {id}: ScheduleCommandParams,
    {filter}: ScheduleCommandOptions = {},
  ) {
    if (!nativeScheduleDetailSupportsFilter(filter)) {
      throw new Error('Native schedule detail filter is not supported');
    }
    return new Response(await fetchNativeSchedule(this.http, id));
  }

  create(args: NativeScheduleCreateArgs) {
    return createNativeSchedule(this.http, args);
  }

  save(args: NativeSchedulePatchArgs) {
    return patchNativeSchedule(this.http, args);
  }

  async delete({id}: ScheduleCommandParams) {
    await deleteNativeSchedule(this.http, id);
    return new Response(undefined);
  }

  export({id}: ScheduleCommandParams) {
    return exportNativeScheduleMetadata(this.http, id);
  }

  clone({id}: ScheduleCommandParams) {
    return cloneNativeSchedule(this.http, id);
  }
}

export class SchedulesCommand {
  private readonly http: Http;

  constructor(http: Http) {
    this.http = http;
  }

  async get(params: SchedulesCommandParams = {}) {
    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeSchedules(
      this.http,
      nativeSchedulesQueryFromFilter(filter),
    );
    return new Response(nativeResponse.schedules, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(params: SchedulesCommandParams = {}) {
    const filter = filterFromCommandParams(params).all();
    const schedules: Schedule[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; schedules.length < total; page += 1) {
      const nativeResponse = await fetchNativeSchedules(this.http, {
        ...nativeSchedulesQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      schedules.push(...nativeResponse.schedules);
      total = nativeResponse.page.total;
      if (nativeResponse.schedules.length === 0) {
        break;
      }
    }

    return new Response(
      schedules,
      nativeCollectionMeta(
        filter,
        schedules,
        Number.isFinite(total) ? total : 0,
      ),
    );
  }

  export(schedules: Schedule[]) {
    return this.exportByIds(scheduleIds(schedules));
  }

  exportByIds(ids: string[]) {
    return exportNativeSchedulesMetadata(this.http, ids);
  }

  async exportByFilter(filter: Filter) {
    const schedules: Schedule[] = [];
    if (shouldApplyToAllFilteredSchedules(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; schedules.length < total; page += 1) {
        const nativeResponse = await fetchNativeSchedules(this.http, {
          ...nativeSchedulesQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        schedules.push(...nativeResponse.schedules);
        total = nativeResponse.page.total;
        if (nativeResponse.schedules.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativeSchedules(
        this.http,
        nativeSchedulesQueryFromFilter(filter),
      );
      schedules.push(...nativeResponse.schedules);
    }

    return this.exportByIds(scheduleIds(schedules));
  }

  async delete(schedules: Schedule[]) {
    const response = await this.deleteByIds(scheduleIds(schedules));
    return response.setData(schedules);
  }

  async deleteByIds(ids: string[]) {
    const deletedIds: string[] = [];
    await this.deleteIds(ids, deletedIds);
    return new Response(deletedIds);
  }

  async deleteByFilter(filter: Filter) {
    const deletedSchedules: Schedule[] = [];
    const deletedIds: string[] = [];
    const query = nativeSchedulesQueryFromFilter(filter);
    const deleteAll = shouldApplyToAllFilteredSchedules(filter);
    let hasMore = true;

    while (hasMore) {
      const nativeResponse = await fetchNativeSchedules(this.http, {
        ...query,
        ...(deleteAll ? {page: 1, pageSize: NATIVE_COMMAND_PAGE_SIZE} : {}),
      });
      const schedules = nativeResponse.schedules;
      hasMore = deleteAll && schedules.length > 0;
      if (schedules.length === 0) {
        break;
      }
      await this.deleteIds(scheduleIds(schedules), deletedIds);
      deletedSchedules.push(...schedules);
    }

    return new Response(deletedSchedules);
  }

  private async deleteIds(ids: string[], deletedIds: string[]) {
    for (const [index, id] of ids.entries()) {
      try {
        await deleteNativeSchedule(this.http, id);
      } catch (cause) {
        throw new NativeScheduleBulkDeleteError(
          [...deletedIds],
          id,
          ids.slice(index),
          cause,
        );
      }
      deletedIds.push(id);
    }
  }
}

export const createNativeSchedule = async (
  gmp: NativeApiGmp,
  {name, comment = '', timezone, icalendar}: NativeScheduleCreateArgs,
): Promise<Response<{id: string}>> => {
  const payload = await writeNativeJson<NativeSchedulePayload>(
    gmp,
    'api/v1/schedules',
    {
      name,
      comment,
      ...(timezone !== undefined ? {timezone} : {}),
      icalendar,
    },
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
  {id, name, comment, icalendar, timezone}: NativeSchedulePatchArgs,
): Promise<Response<{id: string}>> => {
  const body = {
    ...(name !== undefined ? {name} : {}),
    ...(comment !== undefined ? {comment} : {}),
    ...(icalendar !== undefined ? {icalendar} : {}),
    ...(timezone !== undefined ? {timezone} : {}),
  };
  const payload = await writeNativeJson<NativeSchedulePayload>(
    gmp,
    `api/v1/schedules/${encodeURIComponent(id)}`,
    body,
    'PATCH',
  );
  return new Response({id: stringValue(payload.id)});
};
