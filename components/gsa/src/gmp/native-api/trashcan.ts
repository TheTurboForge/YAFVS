/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
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

export interface NativeTrashcanRestoreArgs {
  id: string;
  entityType: EntityType;
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
      ...(gmp.session.token ? {'X-TurboVAS-Token': gmp.session.token} : {}),
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

const RESTORE_PATHS: Partial<Record<EntityType, string>> = {
  filter: 'filters',
  portlist: 'port-lists',
  reportconfig: 'report-configs',
  scanconfig: 'scan-configs',
  schedule: 'schedules',
  tag: 'tags',
  target: 'targets',
};

export const supportsNativeTrashcanRestore = (
  entityType?: EntityType,
): entityType is keyof typeof RESTORE_PATHS =>
  entityType !== undefined && RESTORE_PATHS[entityType] !== undefined;

export const supportsNativeTrashcanDelete = supportsNativeTrashcanRestore;

export const fetchNativeTrashcanSummary = async (
  gmp: NativeTrashcanApiGmp,
): Promise<NativeTrashcanSummary> =>
  fetchNativeJson<NativeTrashcanSummary>(gmp, 'api/v1/trashcan/summary', {
    token: gmp.session.token,
  });

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
  const path = RESTORE_PATHS[entityType];
  if (path === undefined) {
    throw new Error(`Native trash delete is not available for ${entityType}`);
  }
  await deleteNative(gmp, `api/v1/${path}/${encodeURIComponent(id)}/trash`);
};
