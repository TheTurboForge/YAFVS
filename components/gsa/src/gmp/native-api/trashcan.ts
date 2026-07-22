/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type {UrlParams} from 'gmp/http/utils';
import type {EntityType} from 'gmp/utils/entity-type';

interface NativeApiSession {
  readonly jwt?: string;
  readonly token?: string;
}

export interface NativeTrashcanApiGmp {
  readonly session: NativeApiSession;
  buildUrl(path: string, params?: UrlParams): string;
}

export interface NativeTrashcanSummaryItem {
  resource_type: string;
  title: string;
  count: number;
}

export interface NativeTrashcanSummary {
  items: NativeTrashcanSummaryItem[];
  total: number;
}

export interface NativeTrashcanEmptyPreviewItem {
  resource_type: string;
  count: number;
}

export interface NativeTrashcanEmptyPreview {
  scope: 'operator';
  items: NativeTrashcanEmptyPreviewItem[];
  total: number;
  snapshot_digest: string;
}

export interface NativeTrashcanEmptyResult {
  scope: 'operator';
  deleted_total: number;
}

const CANONICAL_EMPTY_PREVIEW_RESOURCE_TYPES = [
  'configs',
  'alerts',
  'credentials',
  'filters',
  'overrides',
  'port_lists',
  'scanners',
  'schedules',
  'tags',
  'targets',
  'tasks',
  'report_formats',
] as const;

const canonicalEmptyPreviewResourceTypes = new Set<string>(
  CANONICAL_EMPTY_PREVIEW_RESOURCE_TYPES,
);

export interface NativeTrashcanItem {
  id: string;
  resource_type: string;
  entity_type: EntityType;
  title: string;
  name: string;
  comment?: string | null;
  creation_time?: number | null;
  modification_time?: number | null;
}

interface NativeTrashcanPage {
  page?: number;
  page_size?: number;
  total?: number;
}

interface NativeTrashcanItemsPayload {
  page?: NativeTrashcanPage;
  items?: NativeTrashcanItem[];
}

export interface NativeTrashcanRestoreArgs {
  id: string;
  entityType: EntityType;
}

export class NativeTrashcanEmptyPreviewChangedError extends Error {
  constructor() {
    super(
      'Trashcan contents changed after preview; request a new empty preview before retrying.',
    );
    this.name = 'NativeTrashcanEmptyPreviewChangedError';
  }
}

export class NativeTrashcanEmptyIndeterminateError extends Error {
  constructor() {
    super(
      'The Trashcan empty result could not be confirmed. Refresh the Trashcan and obtain a new preview before retrying.',
    );
    this.name = 'NativeTrashcanEmptyIndeterminateError';
  }
}

const fetchNativeJson = async <T>(
  gmp: NativeTrashcanApiGmp,
  path: string,
  params: UrlParams = {},
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

const deleteNative = async (
  gmp: NativeTrashcanApiGmp,
  path: string,
): Promise<void> => {
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
  gmp: NativeTrashcanApiGmp,
  path: string,
  body: unknown = {},
): Promise<T> => {
  const response = await fetch(gmp.buildUrl(path), {
    method: 'POST',
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

const NATIVE_TRASH_PATHS: Partial<Record<EntityType, string>> = {
  alert: 'alerts',
  filter: 'filters',
  override: 'overrides',
  portlist: 'port-lists',
  scanconfig: 'scan-configs',
  scanner: 'scanners',
  schedule: 'schedules',
  tag: 'tags',
  target: 'targets',
};

const RESTORE_PATHS: Partial<Record<EntityType, string>> = {
  ...NATIVE_TRASH_PATHS,
  task: 'tasks',
};

const DELETE_PATHS = NATIVE_TRASH_PATHS;

export const supportsNativeTrashcanRestore = (
  entityType?: EntityType,
): entityType is keyof typeof RESTORE_PATHS =>
  entityType !== undefined && RESTORE_PATHS[entityType] !== undefined;

export const supportsNativeTrashcanDelete = (
  entityType?: EntityType,
): entityType is keyof typeof DELETE_PATHS =>
  entityType !== undefined && DELETE_PATHS[entityType] !== undefined;

export const fetchNativeTrashcanSummary = async (
  gmp: NativeTrashcanApiGmp,
): Promise<NativeTrashcanSummary> =>
  fetchNativeJson<NativeTrashcanSummary>(gmp, 'api/v1/trashcan/summary', {
    token: gmp.session.token,
  });

const isNonNegativeSafeInteger = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;

const isSnapshotDigest = (value: unknown): value is string =>
  typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);

const isNativeTrashcanEmptyPreview = (
  value: unknown,
): value is NativeTrashcanEmptyPreview => {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const preview = value as Partial<NativeTrashcanEmptyPreview>;
  if (
    preview.scope !== 'operator' ||
    !isNonNegativeSafeInteger(preview.total) ||
    !isSnapshotDigest(preview.snapshot_digest) ||
    !Array.isArray(preview.items) ||
    preview.items.length !== CANONICAL_EMPTY_PREVIEW_RESOURCE_TYPES.length
  ) {
    return false;
  }

  let countTotal = 0;
  const resourceTypes = new Set<string>();
  for (const item of preview.items) {
    if (typeof item !== 'object' || item === null) {
      return false;
    }
    const previewItem = item as Partial<NativeTrashcanEmptyPreviewItem>;
    if (
      typeof previewItem.resource_type !== 'string' ||
      !canonicalEmptyPreviewResourceTypes.has(previewItem.resource_type) ||
      resourceTypes.has(previewItem.resource_type) ||
      !isNonNegativeSafeInteger(previewItem.count) ||
      countTotal > Number.MAX_SAFE_INTEGER - previewItem.count
    ) {
      return false;
    }
    resourceTypes.add(previewItem.resource_type);
    countTotal += previewItem.count;
  }

  return (
    resourceTypes.size === CANONICAL_EMPTY_PREVIEW_RESOURCE_TYPES.length &&
    countTotal === preview.total
  );
};

const isNativeTrashcanEmptyResult = (
  value: unknown,
): value is NativeTrashcanEmptyResult => {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const result = value as Partial<NativeTrashcanEmptyResult>;
  return (
    result.scope === 'operator' &&
    isNonNegativeSafeInteger(result.deleted_total)
  );
};

export const fetchNativeTrashcanEmptyPreview = async (
  gmp: NativeTrashcanApiGmp,
): Promise<NativeTrashcanEmptyPreview> => {
  const preview = await fetchNativeJson<unknown>(
    gmp,
    'api/v1/trashcan/empty-preview',
    {token: gmp.session.token},
  );
  if (!isNativeTrashcanEmptyPreview(preview)) {
    throw new Error('Native Trashcan empty preview response is invalid');
  }
  return preview;
};

export const emptyNativeTrashcan = async (
  gmp: NativeTrashcanApiGmp,
  expectedTotal: number,
  expectedSnapshotDigest: string,
): Promise<NativeTrashcanEmptyResult> => {
  if (
    !isNonNegativeSafeInteger(expectedTotal) ||
    !isSnapshotDigest(expectedSnapshotDigest)
  ) {
    throw new Error('Native Trashcan empty preview confirmation is invalid');
  }

  let response: globalThis.Response;
  try {
    response = await fetch(gmp.buildUrl('api/v1/trashcan/empty'), {
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
      body: JSON.stringify({
        acknowledge_permanent_deletion: true,
        expected_total: expectedTotal,
        expected_snapshot_digest: expectedSnapshotDigest,
      }),
    });
  } catch {
    throw new NativeTrashcanEmptyIndeterminateError();
  }

  if (response.status === 409) {
    throw new NativeTrashcanEmptyPreviewChangedError();
  }
  if (!response.ok) {
    if (response.status >= 500) {
      throw new NativeTrashcanEmptyIndeterminateError();
    }
    throw new Error(`Native API request failed with status ${response.status}`);
  }

  try {
    const result = (await response.json()) as unknown;
    if (
      !isNativeTrashcanEmptyResult(result) ||
      result.deleted_total !== expectedTotal
    ) {
      throw new Error('Native Trashcan empty response is invalid');
    }
    return result;
  } catch {
    throw new NativeTrashcanEmptyIndeterminateError();
  }
};

export const fetchNativeTrashcanItems = async (
  gmp: NativeTrashcanApiGmp,
): Promise<NativeTrashcanItem[]> => {
  const items: NativeTrashcanItem[] = [];
  let total = Number.POSITIVE_INFINITY;
  const pageSize = 500;

  for (let page = 1; items.length < total; page += 1) {
    const payload = await fetchNativeJson<NativeTrashcanItemsPayload>(
      gmp,
      'api/v1/trashcan/items',
      {
        token: gmp.session.token,
        page,
        page_size: pageSize,
        sort: 'resource_type',
      },
    );
    const pageItems = payload.items ?? [];
    items.push(...pageItems);
    total = payload.page?.total ?? items.length;
    if (pageItems.length === 0) {
      break;
    }
  }

  return items;
};

export const restoreNativeTrashcanEntity = async (
  gmp: NativeTrashcanApiGmp,
  {id, entityType}: NativeTrashcanRestoreArgs,
): Promise<void> => {
  const path = RESTORE_PATHS[entityType];
  if (path === undefined) {
    throw new Error(`Native restore is not available for ${entityType}`);
  }
  await writeNativeJson(
    gmp,
    `api/v1/${path}/${encodeURIComponent(id)}/restore`,
  );
};

export const deleteNativeTrashcanEntity = async (
  gmp: NativeTrashcanApiGmp,
  {id, entityType}: NativeTrashcanRestoreArgs,
): Promise<void> => {
  const path = DELETE_PATHS[entityType];
  if (path === undefined) {
    throw new Error(`Native trash delete is not available for ${entityType}`);
  }
  await deleteNative(gmp, `api/v1/${path}/${encodeURIComponent(id)}/trash`);
};
