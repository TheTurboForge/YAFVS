/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntitiesCommand from 'gmp/commands/entities';
import type {HttpCommandInputParams} from 'gmp/commands/http';
import {
  canUseNativeApi,
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import type Filter from 'gmp/models/filter';
import Target from 'gmp/models/target';
import {
  deleteNativeTarget,
  exportNativeTargetsMetadata,
  fetchNativeTargets,
  nativeTargetQueryFromFilter,
} from 'gmp/native-api/targets';

export class NativeTargetBulkDeleteError extends Error {
  readonly deletedIds: readonly string[];
  readonly failedId: string;
  readonly pendingIds: readonly string[];

  constructor(
    deletedIds: string[],
    failedId: string,
    pendingIds: string[],
    cause: unknown,
  ) {
    super(
      `Native target bulk delete stopped at ${failedId} after deleting ${deletedIds.length} target(s).`,
      {cause},
    );
    this.name = 'NativeTargetBulkDeleteError';
    this.deletedIds = Object.freeze([...deletedIds]);
    this.failedId = failedId;
    this.pendingIds = Object.freeze([...pendingIds]);
    Object.freeze(this);
  }
}

const shouldApplyToAllFilteredTargets = (filter: Filter): boolean => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

const requireNativeTargetApi = (http: Http) => {
  if (!canUseNativeApi(http)) {
    throw new Error('Native target API is required for targets command');
  }
};

const requiredTargetId = (id: unknown, index: number): string => {
  if (typeof id !== 'string' || id.trim().length === 0) {
    throw new Error(`Native target deletion requires an ID at index ${index}`);
  }
  return id;
};

const requireUniqueTargetIds = (ids: readonly unknown[]): string[] => {
  const validatedIds = ids.map(requiredTargetId);
  const seenIds = new Set<string>();
  for (const id of validatedIds) {
    if (seenIds.has(id)) {
      throw new Error(`Native target deletion received duplicate ID ${id}`);
    }
    seenIds.add(id);
  }
  return validatedIds;
};

const targetIds = (targets: Target[]): string[] =>
  requireUniqueTargetIds(targets.map(target => target.id));

class TargetsCommand extends EntitiesCommand<Target> {
  constructor(http: Http) {
    super(http, 'target', Target);
  }

  protected getEntitiesResponse(): never {
    throw new Error('Target XML collection parsing has been retired');
  }

  async get(params: HttpCommandInputParams = {}) {
    requireNativeTargetApi(this.http);
    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeTargets(
      this.http,
      nativeTargetQueryFromFilter(filter),
    );
    return new Response(nativeResponse.targets, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(params: HttpCommandInputParams = {}) {
    requireNativeTargetApi(this.http);
    const filter = filterFromCommandParams(params).all();
    const targets: Target[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; targets.length < total; page += 1) {
      const nativeResponse = await fetchNativeTargets(this.http, {
        ...nativeTargetQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      targets.push(...nativeResponse.targets);
      total = nativeResponse.page.total;
      if (nativeResponse.targets.length === 0) {
        break;
      }
    }

    return new Response(
      targets,
      nativeCollectionMeta(filter, targets, Number.isFinite(total) ? total : 0),
    );
  }

  exportByIds(ids: string[]) {
    requireNativeTargetApi(this.http);
    return exportNativeTargetsMetadata(this.http, ids);
  }

  export(entities: Target[]) {
    return this.exportByIds(
      entities.flatMap(entity => (entity.id === undefined ? [] : [entity.id])),
    );
  }

  async exportByFilter(filter) {
    requireNativeTargetApi(this.http);
    const targets: Target[] = [];
    if (shouldApplyToAllFilteredTargets(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; targets.length < total; page += 1) {
        const nativeResponse = await fetchNativeTargets(this.http, {
          ...nativeTargetQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        targets.push(...nativeResponse.targets);
        total = nativeResponse.page.total;
        if (nativeResponse.targets.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativeTargets(
        this.http,
        nativeTargetQueryFromFilter(filter),
      );
      targets.push(...nativeResponse.targets);
    }

    return exportNativeTargetsMetadata(
      this.http,
      targets.flatMap(target => (target.id === undefined ? [] : [target.id])),
    );
  }

  async delete(targets: Target[]) {
    requireNativeTargetApi(this.http);
    const ids = targetIds(targets);
    await this.deleteIds(ids);
    return new Response(targets);
  }

  async deleteByIds(ids: string[]) {
    requireNativeTargetApi(this.http);
    const validatedIds = requireUniqueTargetIds(ids);
    return new Response(await this.deleteIds(validatedIds));
  }

  async deleteByFilter(filter: Filter) {
    requireNativeTargetApi(this.http);
    const query = nativeTargetQueryFromFilter(filter);
    let targets: Target[];

    if (shouldApplyToAllFilteredTargets(filter)) {
      const firstTargets = await this.traverseAllFilteredTargets(query);
      const firstIds = targetIds(firstTargets);
      targets = await this.traverseAllFilteredTargets(query);
      const ids = targetIds(targets);
      if (
        firstIds.length !== ids.length ||
        firstIds.some((id, index) => id !== ids[index])
      ) {
        throw new Error(
          'Native target bulk delete preflight stabilization detected candidate-set drift',
        );
      }
    } else {
      const nativeResponse = await fetchNativeTargets(this.http, query);
      targets = nativeResponse.targets;
    }

    const ids = targetIds(targets);
    await this.deleteIds(ids);
    return new Response(targets);
  }

  private async traverseAllFilteredTargets(
    query: ReturnType<typeof nativeTargetQueryFromFilter>,
  ): Promise<Target[]> {
    const targets: Target[] = [];
    const seenIds = new Set<string>();
    let traversalTotal: number | undefined;

    for (let page = 1; ; page += 1) {
      const nativeResponse = await fetchNativeTargets(this.http, {
        ...query,
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      if (traversalTotal === undefined) {
        traversalTotal = nativeResponse.page.total;
      } else if (nativeResponse.page.total !== traversalTotal) {
        throw new Error(
          'Native target bulk delete preflight detected collection drift',
        );
      }
      for (const target of nativeResponse.targets) {
        const id = requiredTargetId(target.id, targets.length);
        if (seenIds.has(id)) {
          throw new Error(
            'Native target bulk delete preflight detected duplicate-ID drift',
          );
        }
        seenIds.add(id);
        targets.push(target);
      }
      if (targets.length === traversalTotal) {
        break;
      }
      if (
        nativeResponse.targets.length === 0 ||
        targets.length > traversalTotal ||
        page >= traversalTotal
      ) {
        throw new Error(
          'Native target bulk delete preflight detected collection drift',
        );
      }
    }
    if (targets.length !== traversalTotal) {
      throw new Error(
        'Native target bulk delete preflight detected collection drift',
      );
    }
    return targets;
  }

  private async deleteIds(ids: readonly string[]): Promise<string[]> {
    const deletedIds: string[] = [];
    for (const [index, id] of ids.entries()) {
      try {
        await deleteNativeTarget(this.http, id);
        deletedIds.push(id);
      } catch (cause) {
        throw new NativeTargetBulkDeleteError(
          deletedIds,
          id,
          ids.slice(index + 1),
          cause,
        );
      }
    }
    return deletedIds;
  }
}

export default TargetsCommand;
