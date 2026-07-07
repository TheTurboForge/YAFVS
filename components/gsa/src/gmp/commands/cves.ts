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
import Cve from 'gmp/models/cve';
import Filter from 'gmp/models/filter';
import {type Element} from 'gmp/models/model';
import {
  exportNativeCvesMetadata,
  fetchNativeCves,
  nativeCvesQueryFromFilter,
} from 'gmp/native-api/cves';
import {isDefined} from 'gmp/utils/identity';

const infoFilter = (info: Element) => isDefined(info.cve);

const shouldExportAllByFilter = (filter: Filter): boolean => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

class CvesCommand extends InfoEntitiesCommand<Cve> {
  constructor(http: Http) {
    super(http, 'cve', Cve, infoFilter);
  }

  export(entities: Cve[]) {
    return this.exportByIds(entities.map(entity => entity.id as string));
  }

  exportByIds(ids: string[]) {
    return exportNativeCvesMetadata(this.http, ids);
  }

  async exportByFilter(filter: Filter) {
    const cves: Cve[] = [];
    if (shouldExportAllByFilter(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; cves.length < total; page += 1) {
        const nativeResponse = await fetchNativeCves(this.http, {
          ...nativeCvesQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        cves.push(...nativeResponse.cves);
        total = nativeResponse.page.total;
        if (nativeResponse.cves.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativeCves(
        this.http,
        nativeCvesQueryFromFilter(filter),
      );
      cves.push(...nativeResponse.cves);
    }

    return exportNativeCvesMetadata(
      this.http,
      cves.map(cve => cve.id as string),
    );
  }

  async get(params: HttpCommandInputParams = {}) {
    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeCves(
      this.http,
      nativeCvesQueryFromFilter(filter),
    );
    return new Response(nativeResponse.cves, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(params: HttpCommandInputParams = {}) {
    const filter = filterFromCommandParams(params).all();
    const cves: Cve[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; cves.length < total; page += 1) {
      const nativeResponse = await fetchNativeCves(this.http, {
        ...nativeCvesQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      cves.push(...nativeResponse.cves);
      total = nativeResponse.page.total;
      if (nativeResponse.cves.length === 0) {
        break;
      }
    }

    return new Response(
      cves,
      nativeCollectionMeta(filter, cves, Number.isFinite(total) ? total : 0),
    );
  }

  getCreatedAggregates({filter}: {filter?: Filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'cve',
      group_column: 'created',
      filter,
    });
  }

  getSeverityAggregates({filter}: {filter?: Filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'cve',
      group_column: 'severity',
      filter,
    });
  }
}

export default CvesCommand;
