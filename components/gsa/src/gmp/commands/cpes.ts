/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import InfoEntitiesCommand from 'gmp/commands/info-entities';
import type {HttpCommandInputParams} from 'gmp/commands/http';
import {
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import Cpe from 'gmp/models/cpe';
import Filter from 'gmp/models/filter';
import {type Element} from 'gmp/models/model';
import {
  exportNativeCpesMetadata,
  fetchNativeCpes,
  nativeCpesQueryFromFilter,
} from 'gmp/native-api/cpes';
import {isDefined} from 'gmp/utils/identity';

const infoFilter = (info: Element) => isDefined(info.cpe);

const shouldExportAllByFilter = (filter: Filter): boolean => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

class CpesCommand extends InfoEntitiesCommand<Cpe> {
  constructor(http: Http) {
    super(http, 'cpe', Cpe, infoFilter);
  }

  export(entities: Cpe[]) {
    return this.exportByIds(entities.map(entity => entity.id as string));
  }

  exportByIds(ids: string[]) {
    return exportNativeCpesMetadata(this.http, ids);
  }

  async exportByFilter(filter: Filter) {
    const cpes: Cpe[] = [];
    if (shouldExportAllByFilter(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; cpes.length < total; page += 1) {
        const nativeResponse = await fetchNativeCpes(this.http, {
          ...nativeCpesQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        cpes.push(...nativeResponse.cpes);
        total = nativeResponse.page.total;
        if (nativeResponse.cpes.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativeCpes(
        this.http,
        nativeCpesQueryFromFilter(filter),
      );
      cpes.push(...nativeResponse.cpes);
    }

    return exportNativeCpesMetadata(
      this.http,
      cpes.map(cpe => cpe.id as string),
    );
  }

  async get(params: HttpCommandInputParams = {}) {
    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeCpes(
      this.http,
      nativeCpesQueryFromFilter(filter),
    );
    return new Response(nativeResponse.cpes, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(params: HttpCommandInputParams = {}) {
    const filter = filterFromCommandParams(params).all();
    const cpes: Cpe[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; cpes.length < total; page += 1) {
      const nativeResponse = await fetchNativeCpes(this.http, {
        ...nativeCpesQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      cpes.push(...nativeResponse.cpes);
      total = nativeResponse.page.total;
      if (nativeResponse.cpes.length === 0) {
        break;
      }
    }

    return new Response(
      cpes,
      nativeCollectionMeta(filter, cpes, Number.isFinite(total) ? total : 0),
    );
  }

  getCreatedAggregates({filter}: {filter?: Filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'cpe',
      group_column: 'created',
      filter,
    });
  }

  getSeverityAggregates({filter}: {filter?: Filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'cpe',
      group_column: 'severity',
      filter,
    });
  }
}

export default CpesCommand;
