/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import type {HttpCommandInputParams} from 'gmp/commands/http';
import {
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import type {UrlParams} from 'gmp/http/utils';
import ActionResult from 'gmp/models/action-result';
import type Filter from 'gmp/models/filter';
import {filterString} from 'gmp/models/filter/utils';
import PortList from 'gmp/models/port-list';
import {NO_VALUE, YES_VALUE} from 'gmp/parser';

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

interface NativePortCountPayload {
  all?: number;
  tcp?: number;
  udp?: number;
}

interface NativePortRangePayload {
  id: string;
  protocol: string;
  start: number;
  end: number;
  comment?: string;
}

interface NativePortListTargetPayload {
  id: string;
  name: string;
}

interface NativeUserTagPayload {
  id: string;
  name: string;
  value: string;
  comment: string;
}

interface NativePortListPayload {
  id: string;
  name: string;
  comment?: string;
  port_count?: NativePortCountPayload;
  port_ranges?: NativePortRangePayload[];
  targets?: NativePortListTargetPayload[];
  user_tags?: NativeUserTagPayload[];
  predefined?: boolean;
  deprecated?: boolean;
  created_at?: string;
  modified_at?: string;
}

interface NativePortListsPayload {
  page?: Partial<NativePage>;
  items?: NativePortListPayload[];
}

interface NativePortListCreateRangePayload {
  protocol: string;
  start: number;
  end: number;
  comment?: string;
}

export interface NativePortListCreateRequest {
  name: string;
  comment?: string;
  port_ranges: NativePortListCreateRangePayload[];
}

export interface NativePortListImportRequest {
  xml_file: string;
}

export interface NativePortListRangeCommandRequest {
  portListId: string;
  portRangeStart: number;
  portRangeEnd: number;
  portType: string;
  comment?: string;
}

export interface NativePortListsQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
  predefined?: string;
}

export interface NativePortListsResponse {
  portLists: PortList[];
  counts: CollectionCounts;
  page: NativePage;
}

export type FromFile = typeof FROM_FILE | typeof NOT_FROM_FILE;

export interface PortListCommandCreateParams {
  name: string;
  comment?: string;
  fromFile?: FromFile;
  portRange?: string;
  file?: File;
}

export interface PortListCommandSaveParams {
  id: string;
  name: string;
  comment?: string;
}

interface PortListCommandCreatePortRangeParams {
  portListId: string;
  portRangeStart: number;
  portRangeEnd: number;
  portType: string;
  comment?: string;
}

interface PortListCommandDeletePortRangeParams {
  id: string;
  portListId: string;
}

interface PortListCommandImportParams {
  xmlFile?: File;
}

interface PortListCommandParams {
  id: string;
  filter?: Filter | string;
}

interface PortListCommandOptions {
  filter?: Filter | string;
}

export const FROM_FILE = YES_VALUE;
export const NOT_FROM_FILE = NO_VALUE;

const PORT_LIST_SORT_FIELDS: Record<string, string> = {
  name: 'name',
  total: 'total',
  tcp: 'tcp',
  udp: 'udp',
  predefined: 'predefined',
  modified: 'modified',
};

export const importNativePortList = async (
  gmp: NativeApiGmp,
  request: NativePortListImportRequest,
): Promise<Response<{id: string}>> => {
  const payload = await writeNativeJson<NativePortListPayload>(
    gmp,
    'api/v1/port-list-imports',
    request,
  );
  return new Response({id: stringValue(payload.id)});
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
  const rawField = stringValue(reverse ?? ascending) || 'name';
  const nativeField = PORT_LIST_SORT_FIELDS[rawField] ?? rawField;
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

export const nativePortListsQueryFromFilter = (
  filter?: Filter,
): NativePortListsQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
    predefined:
      filter?.get('predefined') === undefined
        ? undefined
        : String(filter.get('predefined')),
  };
};

const shouldApplyToAllFilteredPortLists = (filter: Filter): boolean => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

const nativePortListDetailSupportsFilter = (
  filter?: Filter | string,
): boolean => {
  const value = filterString(filter);
  return filter === undefined || value === 'targets=1';
};

const nativePortListCreateRequestFromCommand = ({
  name,
  comment = '',
  fromFile,
  portRange,
}: PortListCommandCreateParams): NativePortListCreateRequest | undefined => {
  if (fromFile === FROM_FILE || portRange === undefined) {
    return undefined;
  }
  let currentProtocol: 'tcp' | 'udp' | undefined;
  const port_ranges = portRange
    .split(/[\n,]+/)
    .map(range => range.trim())
    .filter(range => range.length > 0)
    .map(range => {
      const prefixed = /^(tcp|udp|t|u):(\d+(?:-\d+)?)$/i.exec(range);
      const unprefixed = /^(\d+(?:-\d+)?)$/.exec(range);
      if (prefixed !== null) {
        const protocol = prefixed[1].toLowerCase();
        currentProtocol =
          protocol === 'udp' || protocol === 'u' ? 'udp' : 'tcp';
      }
      const rangeText = prefixed?.[2] ?? unprefixed?.[1];
      if (rangeText === undefined || currentProtocol === undefined) {
        return undefined;
      }
      const [startText, endText] = rangeText.split('-', 2);
      const start = Number.parseInt(startText, 10);
      const end = Number.parseInt(endText ?? startText, 10);
      if (!Number.isInteger(start) || !Number.isInteger(end)) {
        return undefined;
      }
      return {protocol: currentProtocol, start, end};
    });

  if (port_ranges.some(range => range === undefined)) {
    return undefined;
  }

  return {
    name,
    comment,
    port_ranges: port_ranges.filter(range => range !== undefined),
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

const nativePortListToModel = (
  item: NativePortListPayload,
  {detail = false}: {detail?: boolean} = {},
): PortList =>
  PortList.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name),
    comment: stringValue(item.comment),
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    predefined: item.predefined ? YES_VALUE : NO_VALUE,
    deprecated: item.deprecated ? YES_VALUE : NO_VALUE,
    writable: 1,
    port_count: {
      all: String(integerValue(item.port_count?.all)),
      tcp: String(integerValue(item.port_count?.tcp)),
      udp: String(integerValue(item.port_count?.udp)),
    },
    port_ranges: {
      port_range: (item.port_ranges ?? []).map(range => ({
        _id: stringValue(range.id),
        type: range.protocol === 'udp' ? 'udp' : 'tcp',
        start: integerValue(range.start),
        end: integerValue(range.end),
        comment: stringValue(range.comment),
      })),
    },
    targets: {
      target: (item.targets ?? []).map(target => ({
        _id: stringValue(target.id),
        name: stringValue(target.name),
      })),
    },
    user_tags: detail ? nativeUserTagsElement(item.user_tags ?? []) : undefined,
  });

export const fetchNativePortLists = async (
  gmp: NativeApiGmp,
  query: NativePortListsQuery,
): Promise<NativePortListsResponse> => {
  const payload = await fetchNativeJson<NativePortListsPayload>(
    gmp,
    'api/v1/port-lists',
    {
      token: gmp.session.token,
      page: query.page,
      page_size: query.pageSize,
      sort: query.sort,
      filter: query.filter,
      predefined: query.predefined,
    },
  );
  const page = {
    page: integerValue(payload.page?.page, 1),
    page_size: integerValue(payload.page?.page_size, query.pageSize),
    total: integerValue(payload.page?.total),
    sort: stringValue(payload.page?.sort),
    filter: stringValue(payload.page?.filter),
  };
  const portLists = (payload.items ?? []).map(item =>
    nativePortListToModel(item),
  );
  return {
    portLists,
    counts: nativeCounts(page, portLists.length),
    page,
  };
};

export const fetchNativePortList = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<PortList> => {
  const payload = await fetchNativePortListPayload(gmp, id);
  return nativePortListToModel(payload, {detail: true});
};

const fetchNativePortListPayload = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<NativePortListPayload> =>
  fetchNativeJson<NativePortListPayload>(
    gmp,
    `api/v1/port-lists/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );

const patchNativePortListPayload = async (
  gmp: NativeApiGmp,
  id: string,
  request: {
    comment?: string;
    name?: string;
    port_ranges?: NativePortListCreateRangePayload[];
  },
): Promise<NativePortListPayload> =>
  writeNativeJson<NativePortListPayload>(
    gmp,
    `api/v1/port-lists/${encodeURIComponent(id)}`,
    request,
    'PATCH',
  );

export const exportNativePortListMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativePortListPayload>(
    gmp,
    `api/v1/port-lists/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};

export const exportNativePortListsMetadata = async (
  gmp: NativeApiGmp,
  ids: string[],
): Promise<Response<string>> => {
  const portLists = await Promise.all(
    ids.map(id =>
      fetchNativeJson<NativePortListPayload>(
        gmp,
        `api/v1/port-lists/${encodeURIComponent(id)}/export`,
        {token: gmp.session.token},
      ),
    ),
  );
  return new Response(`${JSON.stringify({port_lists: portLists}, null, 2)}\n`);
};

export const createNativePortList = async (
  gmp: NativeApiGmp,
  request: NativePortListCreateRequest,
): Promise<Response<{id: string}>> => {
  const payload = await writeNativeJson<NativePortListPayload>(
    gmp,
    'api/v1/port-lists',
    request,
  );
  return new Response({id: stringValue(payload.id)});
};

export const deleteNativePortList = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<void> =>
  deleteNative(gmp, `api/v1/port-lists/${encodeURIComponent(id)}`);

export const patchNativePortList = async (
  gmp: NativeApiGmp,
  id: string,
  request: {comment: string; name: string},
): Promise<Response<ActionResult>> => {
  const payload = await patchNativePortListPayload(gmp, id, request);
  return new Response(
    new ActionResult({
      action_result: {
        action: 'save_port_list',
        id: stringValue(payload.id),
        message: 'OK',
      },
    }),
  );
};

export const createNativePortRange = async (
  gmp: NativeApiGmp,
  {
    portListId,
    portRangeStart,
    portRangeEnd,
    portType,
    comment,
  }: NativePortListRangeCommandRequest,
): Promise<Response<ActionResult>> => {
  const start = Math.min(portRangeStart, portRangeEnd);
  const end = Math.max(portRangeStart, portRangeEnd);
  const newRange = {
    protocol: portType.toLowerCase(),
    start,
    end,
    ...(comment !== undefined ? {comment} : {}),
  };
  const payload = await writeNativeJson<NativePortListPayload>(
    gmp,
    `api/v1/port-lists/${encodeURIComponent(portListId)}/ranges`,
    newRange,
  );
  const createdRange = (payload.port_ranges ?? []).find(
    range =>
      range.protocol === newRange.protocol &&
      range.start === newRange.start &&
      range.end === newRange.end,
  );
  return new Response(
    new ActionResult({
      action_result: {
        action: 'create_port_range',
        id:
          createdRange?.id !== undefined
            ? stringValue(createdRange.id)
            : stringValue(payload.id),
        message: 'OK',
      },
    }),
  );
};

export class NativePortRangeDeleteError extends Error {
  readonly portListId: string;
  readonly portRangeId: string;

  constructor(portListId: string, portRangeId: string, cause?: unknown) {
    const detail = cause instanceof Error ? `: ${cause.message}` : '';
    super(
      `Native port range deletion failed for ${portRangeId} in ${portListId}${detail}`,
      {cause},
    );
    this.name = 'NativePortRangeDeleteError';
    this.portListId = portListId;
    this.portRangeId = portRangeId;
  }
}

export const deleteNativePortRange = async (
  gmp: NativeApiGmp,
  id: string,
  portListId: string,
): Promise<Response<PortList>> => {
  try {
    await deleteNative(
      gmp,
      `api/v1/port-lists/${encodeURIComponent(portListId)}/ranges/${encodeURIComponent(id)}`,
    );
  } catch (cause) {
    throw new NativePortRangeDeleteError(portListId, id, cause);
  }
  const payload = await fetchNativePortListPayload(gmp, portListId);
  return new Response(nativePortListToModel(payload, {detail: true}));
};

export const cloneNativePortList = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<{id: string}>> => {
  const payload = await writeNativeJson<NativePortListPayload>(
    gmp,
    `api/v1/port-lists/${encodeURIComponent(id)}/clone`,
    {},
  );
  return new Response({id: stringValue(payload.id)});
};

export class NativePortListBulkDeleteError extends Error {
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
      `Native port list bulk delete stopped at ${failedId} after deleting ${deletedIds.length} port list(s).`,
      {cause},
    );
    this.name = 'NativePortListBulkDeleteError';
    this.deletedIds = deletedIds;
    this.failedId = failedId;
    this.pendingIds = pendingIds;
  }
}

const portListIds = (portLists: PortList[]) =>
  portLists.flatMap(portList =>
    portList.id === undefined ? [] : [portList.id],
  );

export class PortListCommand {
  private readonly http: Http;

  constructor(http: Http) {
    this.http = http;
  }

  async get(
    {id}: PortListCommandParams,
    {filter}: PortListCommandOptions = {},
  ) {
    if (!nativePortListDetailSupportsFilter(filter)) {
      throw new Error('Native port list detail filter is not supported');
    }
    return new Response(await fetchNativePortList(this.http, id));
  }

  export({id}: PortListCommandParams) {
    return exportNativePortListMetadata(this.http, id);
  }

  async create(args: PortListCommandCreateParams) {
    const {fromFile, file} = args;
    if (fromFile === FROM_FILE && file !== undefined) {
      return importNativePortList(this.http, {xml_file: await file.text()});
    }
    const nativeRequest = nativePortListCreateRequestFromCommand(args);
    if (nativeRequest === undefined) {
      throw new Error(
        'Native port list create received unsupported payload shape',
      );
    }
    return createNativePortList(this.http, nativeRequest);
  }

  save({id, name, comment = ''}: PortListCommandSaveParams) {
    return patchNativePortList(this.http, id, {comment, name});
  }

  clone({id}: PortListCommandParams) {
    return cloneNativePortList(this.http, id);
  }

  async delete({id}: PortListCommandParams) {
    await deleteNativePortList(this.http, id);
  }

  createPortRange({
    portListId,
    portRangeStart,
    portRangeEnd,
    portType,
    comment,
  }: PortListCommandCreatePortRangeParams) {
    return createNativePortRange(this.http, {
      portListId,
      portRangeStart,
      portRangeEnd,
      portType,
      comment,
    });
  }

  deletePortRange({id, portListId}: PortListCommandDeletePortRangeParams) {
    return deleteNativePortRange(this.http, id, portListId);
  }

  async import({xmlFile}: PortListCommandImportParams) {
    if (xmlFile === undefined) {
      throw new Error(
        'Native port list import received unsupported payload shape',
      );
    }
    return importNativePortList(this.http, {xml_file: await xmlFile.text()});
  }
}

export class PortListsCommand {
  private readonly http: Http;

  constructor(http: Http) {
    this.http = http;
  }

  async get(params: HttpCommandInputParams = {}) {
    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativePortLists(
      this.http,
      nativePortListsQueryFromFilter(filter),
    );
    return new Response(nativeResponse.portLists, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(params: HttpCommandInputParams = {}) {
    const filter = filterFromCommandParams(params).all();
    const portLists: PortList[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; portLists.length < total; page += 1) {
      const nativeResponse = await fetchNativePortLists(this.http, {
        ...nativePortListsQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      portLists.push(...nativeResponse.portLists);
      total = nativeResponse.page.total;
      if (nativeResponse.portLists.length === 0) {
        break;
      }
    }

    return new Response(
      portLists,
      nativeCollectionMeta(
        filter,
        portLists,
        Number.isFinite(total) ? total : 0,
      ),
    );
  }

  export(portLists: PortList[]) {
    return this.exportByIds(portListIds(portLists));
  }

  exportByIds(ids: string[]) {
    return exportNativePortListsMetadata(this.http, ids);
  }

  async exportByFilter(filter: Filter) {
    const portLists: PortList[] = [];
    if (shouldApplyToAllFilteredPortLists(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; portLists.length < total; page += 1) {
        const nativeResponse = await fetchNativePortLists(this.http, {
          ...nativePortListsQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        portLists.push(...nativeResponse.portLists);
        total = nativeResponse.page.total;
        if (nativeResponse.portLists.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativePortLists(
        this.http,
        nativePortListsQueryFromFilter(filter),
      );
      portLists.push(...nativeResponse.portLists);
    }

    return this.exportByIds(portListIds(portLists));
  }

  async delete(portLists: PortList[]) {
    const response = await this.deleteByIds(portListIds(portLists));
    return response.setData(portLists);
  }

  async deleteByIds(ids: string[]) {
    const deletedIds: string[] = [];
    await this.deleteIds(ids, deletedIds);
    return new Response(deletedIds);
  }

  async deleteByFilter(filter: Filter) {
    const deletedPortLists: PortList[] = [];
    const deletedIds: string[] = [];
    const query = nativePortListsQueryFromFilter(filter);
    const deleteAll = shouldApplyToAllFilteredPortLists(filter);
    let hasMore = true;

    while (hasMore) {
      const nativeResponse = await fetchNativePortLists(this.http, {
        ...query,
        ...(deleteAll ? {page: 1, pageSize: NATIVE_COMMAND_PAGE_SIZE} : {}),
      });
      const portLists = nativeResponse.portLists;
      hasMore = deleteAll && portLists.length > 0;
      if (portLists.length === 0) {
        break;
      }
      await this.deleteIds(portListIds(portLists), deletedIds);
      deletedPortLists.push(...portLists);
    }

    return new Response(deletedPortLists);
  }

  private async deleteIds(ids: string[], deletedIds: string[]) {
    for (const [index, id] of ids.entries()) {
      try {
        await deleteNativePortList(this.http, id);
      } catch (cause) {
        throw new NativePortListBulkDeleteError(
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
