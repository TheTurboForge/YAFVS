/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import registerCommand from 'gmp/command';
import EntitiesCommand from 'gmp/commands/entities';
import EntityCommand from 'gmp/commands/entity';
import {
  canUseNativeApi,
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import Response from 'gmp/http/response';
import OperatingSystem from 'gmp/models/os';
import {
  exportNativeOperatingSystemMetadata,
  exportNativeOperatingSystemsMetadata,
  fetchNativeOperatingSystem,
  fetchNativeOperatingSystems,
  nativeOperatingSystemsQueryFromFilter,
} from 'gmp/native-api/operating-systems';

const assertNativeOperatingSystemHttp = http => {
  if (!canUseNativeApi(http)) {
    throw new Error(
      'Operating-system reads and exports require the native HTTP adapter.',
    );
  }
};

const shouldExportAllByFilter = filter => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

class OperatingSystemCommand extends EntityCommand {
  constructor(http) {
    super(http, 'asset', OperatingSystem);
    this.setDefaultParam('asset_type', 'os');
  }

  /** @returns {never} */
  getElementFromRoot(_root) {
    throw new Error('Legacy operating-system XML parsing is retired.');
  }

  async get({id}) {
    assertNativeOperatingSystemHttp(this.http);
    const {operatingSystem} = await fetchNativeOperatingSystem(this.http, id);
    return new Response(operatingSystem);
  }

  async export({id}) {
    assertNativeOperatingSystemHttp(this.http);
    return await exportNativeOperatingSystemMetadata(this.http, id);
  }
}

class OperatingSystemsCommand extends EntitiesCommand {
  constructor(http) {
    super(http, 'asset', OperatingSystem);
    this.setDefaultParam('asset_type', 'os');
  }

  /** @returns {never} */
  getEntitiesResponse(_root) {
    throw new Error('Legacy operating-system XML parsing is retired.');
  }

  async get(params = {}, _options) {
    assertNativeOperatingSystemHttp(this.http);
    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeOperatingSystems(
      this.http,
      nativeOperatingSystemsQueryFromFilter(filter),
    );
    return new Response(nativeResponse.operatingSystems, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(params = {}, _options) {
    assertNativeOperatingSystemHttp(this.http);
    const filter = filterFromCommandParams(params).all();
    const operatingSystems = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; operatingSystems.length < total; page += 1) {
      const nativeResponse = await fetchNativeOperatingSystems(this.http, {
        ...nativeOperatingSystemsQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      operatingSystems.push(...nativeResponse.operatingSystems);
      total = nativeResponse.page.total;
      if (nativeResponse.operatingSystems.length === 0) {
        break;
      }
    }

    return new Response(
      operatingSystems,
      nativeCollectionMeta(
        filter,
        operatingSystems,
        Number.isFinite(total) ? total : 0,
      ),
    );
  }

  getAverageSeverityAggregates({filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'os',
      group_column: 'average_severity',
      filter,
    });
  }

  exportByIds(ids, _assetType) {
    assertNativeOperatingSystemHttp(this.http);
    return exportNativeOperatingSystemsMetadata(this.http, ids);
  }

  export(entities, _assetType) {
    assertNativeOperatingSystemHttp(this.http);
    return this.exportByIds(entities.map(element => element.id));
  }

  async exportByFilter(filter) {
    assertNativeOperatingSystemHttp(this.http);
    const operatingSystems = [];
    if (shouldExportAllByFilter(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; operatingSystems.length < total; page += 1) {
        const nativeResponse = await fetchNativeOperatingSystems(this.http, {
          ...nativeOperatingSystemsQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        operatingSystems.push(...nativeResponse.operatingSystems);
        total = nativeResponse.page.total;
        if (nativeResponse.operatingSystems.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativeOperatingSystems(
        this.http,
        nativeOperatingSystemsQueryFromFilter(filter),
      );
      operatingSystems.push(...nativeResponse.operatingSystems);
    }

    return exportNativeOperatingSystemsMetadata(
      this.http,
      operatingSystems.map(os => os.id),
    );
  }

  getVulnScoreAggregates({filter, max} = {}) {
    return this.getAggregates({
      filter,
      aggregate_type: 'os',
      group_column: 'uuid',
      textColumns: ['name', 'hosts', 'modified'],
      dataColumns: ['average_severity', 'average_severity_score'],
      sort: [
        {
          field: 'average_severity_score',
          direction: 'descending',
          stat: 'max',
        },
        {
          field: 'modified',
          direction: 'descending',
        },
      ],
      maxGroups: max,
    });
  }
}

registerCommand('operatingsystem', OperatingSystemCommand);
registerCommand('operatingsystems', OperatingSystemsCommand);

export {OperatingSystemCommand, OperatingSystemsCommand};
