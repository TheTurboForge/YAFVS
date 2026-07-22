/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import HttpCommand, {type HttpCommandInputParams} from 'gmp/commands/http';
import {
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import type Filter from 'gmp/models/filter';
import {
  deleteNativeFilter,
  exportNativeFiltersMetadata,
  fetchNativeFilter,
  fetchNativeFilters,
  nativeFiltersQueryFromFilter,
} from 'gmp/native-api/filters';

const shouldExportAllByFilter = (filter: Filter): boolean => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

const filterIds = (filters: Filter[]): string[] =>
  filters.map(filter => {
    if (filter.id === undefined) {
      throw new Error('Native filter operation requires a filter id');
    }
    return filter.id;
  });

export class NativeFilterBulkDeleteError extends Error {
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
      `Native filter bulk delete failed for ${failedId} after ${deletedIds.length} committed deletion(s)`,
      {cause},
    );
    this.name = 'NativeFilterBulkDeleteError';
    this.deletedIds = deletedIds;
    this.failedId = failedId;
    this.pendingIds = pendingIds;
  }
}

export class FiltersCommand extends HttpCommand {
  constructor(http: Http) {
    super(http);
  }

  export(entities: Filter[]) {
    return this.exportByIds(filterIds(entities));
  }

  exportByIds(ids: string[]) {
    return exportNativeFiltersMetadata(this.http, ids);
  }

  async exportByFilter(filter: Filter) {
    const filters: Filter[] = [];
    if (shouldExportAllByFilter(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; filters.length < total; page += 1) {
        const nativeResponse = await fetchNativeFilters(this.http, {
          ...nativeFiltersQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        filters.push(...nativeResponse.filters);
        total = nativeResponse.page.total;
        if (nativeResponse.filters.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativeFilters(
        this.http,
        nativeFiltersQueryFromFilter(filter),
      );
      filters.push(...nativeResponse.filters);
    }

    return exportNativeFiltersMetadata(
      this.http,
      filters.map(savedFilter => savedFilter.id as string),
    );
  }

  async get(params: HttpCommandInputParams = {}) {
    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeFilters(
      this.http,
      nativeFiltersQueryFromFilter(filter),
    );
    return new Response(nativeResponse.filters, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(params: HttpCommandInputParams = {}) {
    const filter = filterFromCommandParams(params).all();
    const filters: Filter[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; filters.length < total; page += 1) {
      const nativeResponse = await fetchNativeFilters(this.http, {
        ...nativeFiltersQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      filters.push(...nativeResponse.filters);
      total = nativeResponse.page.total;
      if (nativeResponse.filters.length === 0) {
        break;
      }
    }

    return new Response(
      filters,
      nativeCollectionMeta(filter, filters, Number.isFinite(total) ? total : 0),
    );
  }

  async delete(filters: Filter[]) {
    const response = await this.deleteByIds(filterIds(filters));
    return response.setData(filters);
  }

  async deleteByIds(ids: string[]) {
    const filters = await Promise.all(
      ids.map(id => fetchNativeFilter(this.http, id)),
    );
    this.requireDeletableFilters(filters);
    const deletedIds: string[] = [];
    await this.deleteIds(ids, deletedIds);
    return new Response(deletedIds);
  }

  async deleteByFilter(filter: Filter) {
    const filters: Filter[] = [];
    const deletedIds: string[] = [];
    const query = nativeFiltersQueryFromFilter(filter);
    const deleteAll = shouldExportAllByFilter(filter);

    if (deleteAll) {
      let snapshotTotal: number | undefined;
      const seenIds = new Set<string>();
      for (let page = 1; ; page += 1) {
        const nativeResponse = await fetchNativeFilters(this.http, {
          ...query,
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        if (snapshotTotal === undefined) {
          snapshotTotal = nativeResponse.page.total;
        } else if (nativeResponse.page.total !== snapshotTotal) {
          throw new Error(
            'Native filter bulk delete preflight detected collection drift',
          );
        }
        for (const savedFilter of nativeResponse.filters) {
          const [id] = filterIds([savedFilter]);
          if (!seenIds.has(id)) {
            seenIds.add(id);
            filters.push(savedFilter);
          }
        }
        if (filters.length === snapshotTotal) {
          break;
        }
        if (
          nativeResponse.filters.length === 0 ||
          filters.length > snapshotTotal ||
          page >= snapshotTotal
        ) {
          throw new Error(
            'Native filter bulk delete preflight detected collection drift',
          );
        }
      }
    } else {
      const nativeResponse = await fetchNativeFilters(this.http, {
        ...query,
      });
      filters.push(...nativeResponse.filters);
    }

    this.requireDeletableFilters(filters);
    await this.deleteIds(filterIds(filters), deletedIds);
    return new Response(filters);
  }

  private requireDeletableFilters(filters: Filter[]) {
    const blocked = filters.find(filter => !filter.isWritable());
    if (blocked !== undefined) {
      throw new Error(
        `Native filter bulk delete refused non-writable filter ${blocked.id ?? '(missing id)'}`,
      );
    }
    const inUse = filters.find(filter => filter.isInUse());
    if (inUse !== undefined) {
      throw new Error(
        `Native filter bulk delete refused in-use filter ${inUse.id ?? '(missing id)'}`,
      );
    }
  }

  private async deleteIds(ids: string[], deletedIds: string[]) {
    for (const [index, id] of ids.entries()) {
      try {
        await deleteNativeFilter(this.http, id);
        deletedIds.push(id);
      } catch (cause) {
        throw new NativeFilterBulkDeleteError(
          [...deletedIds],
          id,
          ids.slice(index + 1),
          cause,
        );
      }
    }
  }
}

export default FiltersCommand;
