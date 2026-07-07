/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import InfoEntitiesCommand from 'gmp/commands/info-entities';
import type {
  HttpCommandInputParams,
  HttpCommandOptions,
} from 'gmp/commands/http';
import {
  canUseNativeApi,
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import Filter from 'gmp/models/filter';
import {type Element} from 'gmp/models/model';
import Nvt from 'gmp/models/nvt';
import {
  exportNativeNvtsMetadata,
  fetchNativeNvts,
  nativeNvtsQueryFromFilter,
} from 'gmp/native-api/nvts';
import {isDefined} from 'gmp/utils/identity';

const infoFilter = (info: Element) => isDefined(info.nvt);

const shouldExportAllByFilter = (filter: Filter): boolean => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

class NvtsCommand extends InfoEntitiesCommand<Nvt> {
  constructor(http: Http) {
    super(http, 'nvt', Nvt, infoFilter);
  }

  export(entities: Nvt[]) {
    if (!canUseNativeApi(this.http)) {
      return super.export(entities);
    }

    return this.exportByIds(entities.map(entity => entity.id as string));
  }

  exportByIds(ids: string[]) {
    if (!canUseNativeApi(this.http)) {
      return super.exportByIds(ids);
    }

    return exportNativeNvtsMetadata(this.http, ids);
  }

  async exportByFilter(filter: Filter) {
    if (!canUseNativeApi(this.http)) {
      return super.exportByFilter(filter);
    }

    const nvts: Nvt[] = [];
    if (shouldExportAllByFilter(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; nvts.length < total; page += 1) {
        const nativeResponse = await fetchNativeNvts(this.http, {
          ...nativeNvtsQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        nvts.push(...nativeResponse.nvts);
        total = nativeResponse.page.total;
        if (nativeResponse.nvts.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativeNvts(
        this.http,
        nativeNvtsQueryFromFilter(filter),
      );
      nvts.push(...nativeResponse.nvts);
    }

    return exportNativeNvtsMetadata(
      this.http,
      nvts.map(nvt => nvt.id as string),
    );
  }

  async get(params: HttpCommandInputParams = {}, options?: HttpCommandOptions) {
    if (!canUseNativeApi(this.http)) {
      return super.get(params, options);
    }

    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeNvts(
      this.http,
      nativeNvtsQueryFromFilter(filter),
    );
    return new Response(nativeResponse.nvts, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(
    params: HttpCommandInputParams = {},
    options?: HttpCommandOptions,
  ) {
    if (!canUseNativeApi(this.http)) {
      return super.getAll(params, options);
    }

    const filter = filterFromCommandParams(params).all();
    const nvts: Nvt[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; nvts.length < total; page += 1) {
      const nativeResponse = await fetchNativeNvts(this.http, {
        ...nativeNvtsQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      nvts.push(...nativeResponse.nvts);
      total = nativeResponse.page.total;
      if (nativeResponse.nvts.length === 0) {
        break;
      }
    }

    return new Response(
      nvts,
      nativeCollectionMeta(filter, nvts, Number.isFinite(total) ? total : 0),
    );
  }

  getFamilyAggregates({filter}: {filter?: Filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'nvt',
      group_column: 'family',
      filter,
      dataColumns: ['severity'],
    });
  }

  getSeverityAggregates({filter}: {filter?: Filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'nvt',
      group_column: 'severity',
      filter,
    });
  }

  getQodAggregates({filter}: {filter?: Filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'nvt',
      group_column: 'qod',
      filter,
    });
  }

  getQodTypeAggregates({filter}: {filter?: Filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'nvt',
      group_column: 'qod_type',
      filter,
    });
  }

  getCreatedAggregates({filter}: {filter?: Filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'nvt',
      group_column: 'created',
      filter,
    });
  }
}

export default NvtsCommand;
