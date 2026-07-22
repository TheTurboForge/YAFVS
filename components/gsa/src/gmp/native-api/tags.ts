/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
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
import type Filter from 'gmp/models/filter';
import {filterString} from 'gmp/models/filter/utils';
import Model from 'gmp/models/model';
import ResourceName from 'gmp/models/resource-name';
import Tag from 'gmp/models/tag';
import {
  resourceType as nativeResourceType,
  type ApiType,
  type EntityType,
} from 'gmp/utils/entity-type';

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

interface NativeTagOwnerPayload {
  name?: string;
}

interface NativeTagResourcesSummaryPayload {
  type?: string;
  count?: {
    total?: number;
  };
}

interface NativeTagPayload {
  id: string;
  name?: string;
  comment?: string;
  owner?: NativeTagOwnerPayload;
  resource_type?: string;
  resource_count?: number;
  resources?: NativeTagResourcesSummaryPayload;
  active?: boolean;
  value?: string | number | null;
  writable?: boolean;
  in_use?: boolean;
  orphan?: boolean;
  trash?: boolean;
  permissions?: string[];
  created_at?: string;
  modified_at?: string;
}

interface NativeTagsPayload {
  page?: Partial<NativePage>;
  items?: NativeTagPayload[];
}

interface NativeTagResourcePayload {
  id: string;
  type?: string;
  name?: string;
}

interface NativeTagResourceCollectionPayload {
  tag_id?: string;
  resource_type?: string;
  page?: Partial<NativePage>;
  items?: NativeTagResourcePayload[];
}

interface NativeTagResourceNamesPayload {
  page?: Partial<NativePage>;
  items?: NativeTagResourcePayload[];
}

export interface NativeTagsQuery {
  page: number;
  pageSize: number;
  sort: string;
  filter: string;
  active: string;
  resourceType: string;
  value: string;
}

export interface NativeTagsResponse {
  tags: Tag[];
  counts: CollectionCounts;
  page: NativePage;
}

export interface NativeTagPatchInput {
  active?: boolean;
  comment?: string;
  name?: string;
  value?: string;
  resourceType?: EntityType;
  resources?: NativeTagResourceUpdateInput;
}

export interface NativeTagResourceUpdateInput {
  action: 'add' | 'remove' | 'set';
  resourceIds?: string[];
  resourceSelection?: NativeTagResourceSelectionInput;
}

export type NativeTagResourceSelectionInput =
  | {
      resourceType: 'port_list';
      search?: string;
      predefined?: boolean;
      expectedCount: number;
    }
  | {
      resourceType: 'credential';
      search?: string;
      credentialType?: string;
      expectedCount: number;
    }
  | {
      resourceType: 'scanner';
      search?: string;
      expectedCount: number;
    }
  | {
      resourceType: 'target';
      search?: string;
      expectedCount: number;
    }
  | {
      resourceType: 'user';
      search?: string;
      expectedCount: number;
    };

export interface TagCommandCreateParams {
  active: boolean;
  comment?: string;
  name: string;
  resourceIds?: string[];
  resourceType: EntityType;
  value?: string;
}

export interface TagCommandSaveParams extends TagCommandCreateParams {
  id: string;
  resourceSelection?: NativeTagResourceSelectionInput;
  resourcesAction?: 'add' | 'remove' | 'set';
}

interface TagCommandParams {
  id: string;
}

interface TagCommandOptions {
  filter?: Filter | string;
}

const nativeTagResourceSelectionPayload = (
  selection: NativeTagResourceSelectionInput,
) => ({
  resource_type: selection.resourceType,
  ...(selection.search === undefined || selection.search === ''
    ? {}
    : {search: selection.search}),
  ...(selection.resourceType === 'port_list' &&
  selection.predefined !== undefined
    ? {predefined: selection.predefined}
    : {}),
  ...(selection.resourceType === 'credential' &&
  selection.credentialType !== undefined
    ? {credential_type: selection.credentialType}
    : {}),
  expected_count: selection.expectedCount,
});

const nativeTagResourceUpdatePayload = ({
  action,
  resourceIds,
  resourceSelection,
}: NativeTagResourceUpdateInput) => {
  return {
    action,
    ...(resourceSelection !== undefined
      ? {
          resource_selection:
            nativeTagResourceSelectionPayload(resourceSelection),
        }
      : {resource_ids: resourceIds ?? []}),
  };
};

const TAG_SORT_FIELDS: Record<string, string> = {
  name: 'name',
  value: 'value',
  active: 'active',
  resource_type: 'resource_type',
  resourceCount: 'resource_count',
  resource_count: 'resource_count',
  resources: 'resources',
  created: 'created',
  modified: 'modified',
};

const NATIVE_TAG_RESOURCE_NAME_TYPES = new Set([
  'alert',
  'cert_bund_adv',
  'credential',
  'cpe',
  'cve',
  'dfn_cert_adv',
  'filter',
  'host',
  'nvt',
  'os',
  'override',
  'port_list',
  'report',
  'report_format',
  'result',
  'scanner',
  'schedule',
  'config',
  'target',
  'task',
  'tls_certificate',
  'user',
]);

const stringValue = (value: unknown): string =>
  typeof value === 'string' ? value : '';

const integerValue = (value: unknown, fallback = 0): number => {
  const parsed = Number.parseInt(String(value ?? fallback), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const yesNoValue = (value?: boolean): 0 | 1 => (value === true ? 1 : 0);

const nativeTagResourceNameType = (
  resourceType?: EntityType,
): string | undefined => {
  const type = nativeResourceType(resourceType);
  return type !== undefined && NATIVE_TAG_RESOURCE_NAME_TYPES.has(type)
    ? type
    : undefined;
};

export const canUseNativeTagResourceNames = (
  gmp: {buildUrl?: unknown},
  resourceType?: EntityType,
): boolean =>
  typeof gmp?.buildUrl === 'function' &&
  nativeTagResourceNameType(resourceType) !== undefined;

const nativeSortFromFilter = (filter?: Filter): string => {
  const reverse = filter?.get('sort-reverse');
  const ascending = filter?.get('sort');
  const rawField = stringValue(reverse ?? ascending) || 'name';
  const nativeField = TAG_SORT_FIELDS[rawField] ?? rawField;
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

const nativeActiveFromFilter = (filter?: Filter): string => {
  const value = filter?.get('active');
  if (value === 1 || value === '1') {
    return '1';
  }
  if (value === 0 || value === '0') {
    return '0';
  }
  return '';
};

export const nativeTagsQueryFromFilter = (filter?: Filter): NativeTagsQuery => {
  const pageSize = Math.max(1, integerValue(filter?.get('rows'), 25));
  const first = Math.max(1, integerValue(filter?.get('first'), 1));
  return {
    page: Math.floor((first - 1) / pageSize) + 1,
    pageSize,
    sort: nativeSortFromFilter(filter),
    filter: nativeSearchFromFilter(filter),
    active: nativeActiveFromFilter(filter),
    resourceType: stringValue(filter?.get('resource_type')),
    value: stringValue(filter?.get('value')),
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

const nativeTagToModel = (item: NativeTagPayload): Tag => {
  const resourceType =
    stringValue(item.resource_type) || stringValue(item.resources?.type);
  const resourceCount =
    item.resource_count ?? item.resources?.count?.total ?? 0;
  return Tag.fromElement({
    _id: stringValue(item.id),
    name: stringValue(item.name),
    comment: stringValue(item.comment),
    owner: {name: stringValue(item.owner?.name)},
    creation_time: stringValue(item.created_at),
    modification_time: stringValue(item.modified_at),
    writable: yesNoValue(item.writable),
    in_use: yesNoValue(item.in_use),
    orphan: yesNoValue(item.orphan),
    active: yesNoValue(item.active ?? true),
    trash: yesNoValue(item.trash),
    permissions: {
      permission: (item.permissions ?? ['get_tags']).map(name => ({name})),
    },
    resources: {
      type: resourceType as ApiType,
      count: {total: resourceCount},
    },
    value: item.value ?? undefined,
  });
};

const normalizePage = (
  payloadPage: Partial<NativePage> | undefined,
  query: NativeTagsQuery,
): NativePage => ({
  page: payloadPage?.page ?? query.page,
  page_size: payloadPage?.page_size ?? query.pageSize,
  total: payloadPage?.total ?? 0,
  sort: payloadPage?.sort ?? query.sort,
  filter: payloadPage?.filter ?? query.filter,
});

export const fetchNativeTags = async (
  gmp: NativeApiGmp,
  query: NativeTagsQuery,
): Promise<NativeTagsResponse> => {
  const payload = await fetchNativeJson<NativeTagsPayload>(gmp, 'api/v1/tags', {
    token: gmp.session.token,
    page: query.page,
    page_size: query.pageSize,
    sort: query.sort,
    filter: query.filter,
    active: query.active,
    resource_type: query.resourceType,
    value: query.value,
  });
  const page = normalizePage(payload.page, query);
  const tags = (payload.items ?? []).map(nativeTagToModel);
  return {
    tags,
    counts: nativeCounts(page, tags.length),
    page,
  };
};

export const fetchNativeTag = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Tag> => {
  const payload = await fetchNativeJson<NativeTagPayload>(
    gmp,
    `api/v1/tags/${encodeURIComponent(id)}`,
    {token: gmp.session.token},
  );
  return nativeTagToModel(payload);
};

export const exportNativeTagMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<NativeTagPayload>(
    gmp,
    `api/v1/tags/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};

export const exportNativeTagsMetadata = async (
  gmp: NativeApiGmp,
  ids: string[],
): Promise<Response<string>> => {
  const tags = await Promise.all(
    ids.map(id =>
      fetchNativeJson<NativeTagPayload>(
        gmp,
        `api/v1/tags/${encodeURIComponent(id)}/export`,
        {token: gmp.session.token},
      ),
    ),
  );
  return new Response(`${JSON.stringify({tags}, null, 2)}\n`);
};

export const cloneNativeTag = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<{id: string}>> => {
  const payload = await writeNativeJson<NativeTagPayload>(
    gmp,
    `api/v1/tags/${encodeURIComponent(id)}/clone`,
    {},
  );
  return new Response({id: stringValue(payload.id)});
};

export const deleteNativeTag = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<void> => deleteNative(gmp, `api/v1/tags/${encodeURIComponent(id)}`);

export const createNativeTag = async (
  gmp: NativeApiGmp,
  {
    active,
    comment,
    name,
    resourceIds,
    resourceType,
    value,
  }: TagCommandCreateParams,
): Promise<Response<{id: string}>> => {
  const resourceIdsPayload =
    resourceIds !== undefined && resourceIds.length > 0
      ? {resource_ids: resourceIds}
      : {};
  const payload = await writeNativeJson<NativeTagPayload>(gmp, 'api/v1/tags', {
    active,
    comment: comment ?? '',
    name,
    ...resourceIdsPayload,
    resource_type: nativeResourceType(resourceType),
    value: value ?? '',
  });
  return new Response({id: stringValue(payload.id)});
};

export const patchNativeTag = async (
  gmp: NativeApiGmp,
  id: string,
  {active, comment, name, value, resourceType, resources}: NativeTagPatchInput,
): Promise<Response<{id: string}>> => {
  const resourcesPayload =
    resources === undefined
      ? {}
      : {resources: nativeTagResourceUpdatePayload(resources)};
  const payload = await writeNativeJson<NativeTagPayload>(
    gmp,
    `api/v1/tags/${encodeURIComponent(id)}`,
    {
      active,
      comment,
      name,
      value,
      ...(resourceType === undefined
        ? {}
        : {resource_type: nativeResourceType(resourceType)}),
      ...resourcesPayload,
    },
    'PATCH',
  );
  return new Response({id: stringValue(payload.id)});
};

export const updateNativeTagResources = async (
  gmp: NativeApiGmp,
  id: string,
  request: NativeTagResourceUpdateInput,
): Promise<Response<{id: string}>> => {
  const payload = await writeNativeJson<NativeTagPayload>(
    gmp,
    `api/v1/tags/${encodeURIComponent(id)}/resources`,
    nativeTagResourceUpdatePayload(request),
  );
  return new Response({id: stringValue(payload.id)});
};

export const fetchNativeTagResources = async (
  gmp: NativeApiGmp,
  id: string,
  resourceType: EntityType,
  pageSize: number,
): Promise<Model[]> => {
  const payload = await fetchNativeJson<NativeTagResourceCollectionPayload>(
    gmp,
    `api/v1/tags/${encodeURIComponent(id)}/resources`,
    {
      token: gmp.session.token,
      page: 1,
      page_size: pageSize,
      sort: 'name',
    },
  );
  return (payload.items ?? []).map(item =>
    Model.fromElement(
      {
        _id: stringValue(item.id),
        name: stringValue(item.name),
      },
      resourceType,
    ),
  );
};

export const fetchNativeTagResourceNames = async (
  gmp: NativeApiGmp,
  resourceType: EntityType,
  pageSize: number,
  filter = '',
): Promise<ResourceName[]> => {
  const type = nativeTagResourceNameType(resourceType);
  if (type === undefined) {
    throw new Error(
      `Unsupported native tag resource-name type ${resourceType}`,
    );
  }

  const payload = await fetchNativeJson<NativeTagResourceNamesPayload>(
    gmp,
    `api/v1/tags/resource-names/${encodeURIComponent(type)}`,
    {
      token: gmp.session.token,
      page: 1,
      page_size: pageSize,
      sort: 'name',
      filter,
    },
  );
  return (payload.items ?? []).map(
    item =>
      new ResourceName({
        id: stringValue(item.id),
        name: stringValue(item.name),
        type: resourceType,
      }),
  );
};

const nativeTagDetailSupportsFilter = (filter?: Filter | string): boolean => {
  const value = filterString(filter);
  return (
    filter === undefined || value === 'resources=1' || value === 'alerts=1'
  );
};

const shouldApplyToAllFilteredTags = (filter: Filter): boolean => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

const TAG_DESTRUCTIVE_FILTER_CONTROLS = new Set([
  'first',
  'rows',
  'sort',
  'sort-reverse',
]);

const TAG_DESTRUCTIVE_FILTER_FIELDS = new Set([
  'search',
  'active',
  'resource_type',
]);

const requireSupportedDestructiveTagFilter = (filter: Filter): void => {
  const criteriaTerms = filter
    .getAllTerms()
    .filter(term => !TAG_DESTRUCTIVE_FILTER_CONTROLS.has(term.keyword ?? ''));
  const keyedTerms = criteriaTerms.filter(term => term.keyword !== undefined);
  const literalTerms = criteriaTerms.filter(
    term => term.keyword === undefined && term.relation === undefined,
  );
  const supported = criteriaTerms.every(
    term =>
      (term.keyword === undefined && term.relation === undefined) ||
      (term.keyword !== undefined &&
        TAG_DESTRUCTIVE_FILTER_FIELDS.has(term.keyword) &&
        term.relation === '=' &&
        term.value !== undefined),
  );
  const uniqueFields = new Set(keyedTerms.map(term => term.keyword));
  const active = filter.get('active');
  if (
    !supported ||
    literalTerms.length > 1 ||
    (literalTerms.length > 0 && keyedTerms.length > 0) ||
    uniqueFields.size !== keyedTerms.length ||
    (active !== undefined &&
      active !== 0 &&
      active !== 1 &&
      active !== '0' &&
      active !== '1')
  ) {
    throw new Error(
      'Native tag bulk delete requires a losslessly supported filter',
    );
  }
};

const tagIds = (tags: Tag[]): string[] =>
  tags.map(tag => {
    if (tag.id === undefined) {
      throw new Error('Native tag operation requires a tag id');
    }
    return tag.id;
  });

const requireUniqueTagIds = (ids: string[]): void => {
  if (new Set(ids).size !== ids.length) {
    throw new Error('Native tag bulk delete requires unique tag ids');
  }
};

export class TagCommand {
  private readonly http: Http;

  constructor(http: Http) {
    this.http = http;
  }

  async get({id}: TagCommandParams, {filter}: TagCommandOptions = {}) {
    if (!nativeTagDetailSupportsFilter(filter)) {
      throw new Error('Native tag detail filter is not supported');
    }
    return new Response(await fetchNativeTag(this.http, id));
  }

  create(args: TagCommandCreateParams) {
    return createNativeTag(this.http, args);
  }

  save(args: TagCommandSaveParams) {
    if (
      'filter' in args &&
      filterString(
        (args as TagCommandSaveParams & {filter?: Filter | string}).filter,
      )
    ) {
      throw new Error('Raw tag resource filters are not supported');
    }
    const {
      id,
      name,
      comment = '',
      active,
      resourceIds = [],
      resourceSelection,
      resourceType,
      resourcesAction,
      value = '',
    } = args;
    if (resourcesAction === undefined) {
      if (resourceSelection !== undefined) {
        throw new Error('Native tag save selection requires a resource action');
      }
      return patchNativeTag(this.http, id, {active, comment, name, value});
    }
    return patchNativeTag(this.http, id, {
      active,
      comment,
      name,
      value,
      ...(resourcesAction === 'set' ? {resourceType} : {}),
      resources: {
        action: resourcesAction,
        resourceIds,
        resourceSelection,
      },
    });
  }

  export({id}: TagCommandParams) {
    return exportNativeTagMetadata(this.http, id);
  }

  enable({id}: TagCommandParams) {
    return patchNativeTag(this.http, id, {active: true});
  }

  disable({id}: TagCommandParams) {
    return patchNativeTag(this.http, id, {active: false});
  }

  clone({id}: TagCommandParams) {
    return cloneNativeTag(this.http, id);
  }

  async delete({id}: TagCommandParams) {
    await deleteNativeTag(this.http, id);
  }
}

export class NativeTagBulkDeleteError extends Error {
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
      `Native tag bulk delete stopped at ${failedId} after deleting ${deletedIds.length} tag(s).`,
      {cause},
    );
    this.name = 'NativeTagBulkDeleteError';
    this.deletedIds = deletedIds;
    this.failedId = failedId;
    this.pendingIds = pendingIds;
  }
}

export class TagsCommand {
  private readonly http: Http;

  constructor(http: Http) {
    this.http = http;
  }

  async get(params: HttpCommandInputParams = {}) {
    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeTags(
      this.http,
      nativeTagsQueryFromFilter(filter),
    );
    return new Response(nativeResponse.tags, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(params: HttpCommandInputParams = {}) {
    const filter = filterFromCommandParams(params).all();
    const tags: Tag[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; tags.length < total; page += 1) {
      const nativeResponse = await fetchNativeTags(this.http, {
        ...nativeTagsQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      tags.push(...nativeResponse.tags);
      total = nativeResponse.page.total;
      if (nativeResponse.tags.length === 0) {
        break;
      }
    }

    return new Response(
      tags,
      nativeCollectionMeta(filter, tags, Number.isFinite(total) ? total : 0),
    );
  }

  export(tags: Tag[]) {
    return this.exportByIds(tagIds(tags));
  }

  exportByIds(ids: string[]) {
    return exportNativeTagsMetadata(this.http, ids);
  }

  async exportByFilter(filter: Filter) {
    const tags: Tag[] = [];
    if (shouldApplyToAllFilteredTags(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; tags.length < total; page += 1) {
        const nativeResponse = await fetchNativeTags(this.http, {
          ...nativeTagsQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        tags.push(...nativeResponse.tags);
        total = nativeResponse.page.total;
        if (nativeResponse.tags.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativeTags(
        this.http,
        nativeTagsQueryFromFilter(filter),
      );
      tags.push(...nativeResponse.tags);
    }
    return this.exportByIds(tagIds(tags));
  }

  async delete(tags: Tag[]) {
    const response = await this.deleteByIds(tagIds(tags));
    return response.setData(tags);
  }

  async deleteByIds(ids: string[]) {
    requireUniqueTagIds(ids);
    const tags = await Promise.all(
      ids.map(id => fetchNativeTag(this.http, id)),
    );
    this.requireDeletableTags(tags);
    const deletedIds: string[] = [];
    await this.deleteIds(ids, deletedIds);
    return new Response(deletedIds);
  }

  async deleteByFilter(filter: Filter) {
    requireSupportedDestructiveTagFilter(filter);
    const tags: Tag[] = [];
    const deletedIds: string[] = [];
    const query = nativeTagsQueryFromFilter(filter.all());
    let snapshotTotal: number | undefined;
    const seenIds = new Set<string>();
    for (let page = 1; ; page += 1) {
      const nativeResponse = await fetchNativeTags(this.http, {
        ...query,
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      if (snapshotTotal === undefined) {
        snapshotTotal = nativeResponse.page.total;
      } else if (nativeResponse.page.total !== snapshotTotal) {
        throw new Error(
          'Native tag bulk delete preflight detected collection drift',
        );
      }
      for (const tag of nativeResponse.tags) {
        const [id] = tagIds([tag]);
        if (seenIds.has(id)) {
          throw new Error(
            'Native tag bulk delete preflight detected collection drift',
          );
        }
        seenIds.add(id);
        tags.push(tag);
      }
      if (tags.length === snapshotTotal) {
        break;
      }
      if (
        nativeResponse.tags.length === 0 ||
        tags.length > snapshotTotal ||
        page >= snapshotTotal
      ) {
        throw new Error(
          'Native tag bulk delete preflight detected collection drift',
        );
      }
    }

    this.requireDeletableTags(tags);
    const ids = tagIds(tags);
    requireUniqueTagIds(ids);
    await this.deleteIds(ids, deletedIds);
    return new Response(tags);
  }

  private requireDeletableTags(tags: Tag[]) {
    const blocked = tags.find(tag => !tag.isWritable());
    if (blocked !== undefined) {
      throw new Error(
        `Native tag bulk delete refused non-writable tag ${blocked.id ?? '(missing id)'}`,
      );
    }
  }

  private async deleteIds(ids: string[], deletedIds: string[]) {
    for (const [index, id] of ids.entries()) {
      try {
        await deleteNativeTag(this.http, id);
        deletedIds.push(id);
      } catch (cause) {
        throw new NativeTagBulkDeleteError(
          [...deletedIds],
          id,
          ids.slice(index + 1),
          cause,
        );
      }
    }
  }
}
