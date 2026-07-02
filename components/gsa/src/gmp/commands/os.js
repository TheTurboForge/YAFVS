/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import registerCommand from 'gmp/command';
import EntitiesCommand from 'gmp/commands/entities';
import EntityCommand from 'gmp/commands/entity';
import {BULK_SELECT_BY_IDS} from 'gmp/commands/http';
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
  fetchNativeOperatingSystems,
  nativeOperatingSystemsQueryFromFilter,
} from 'gmp/native-api/operating-systems';

class OperatingSystemCommand extends EntityCommand {
  constructor(http) {
    super(http, 'asset', OperatingSystem);
    this.setDefaultParam('asset_type', 'os');
  }

  getElementFromRoot(root) {
    return root.get_asset.get_assets_response.asset;
  }

  async export({id}) {
    if (canUseNativeApi(this.http)) {
      try {
        return await exportNativeOperatingSystemMetadata(this.http, id);
      } catch {
        // Keep inherited bulk export responsible for legacy OS export behavior.
      }
    }
    return super.export({id});
  }
}

class OperatingSystemsCommand extends EntitiesCommand {
  constructor(http) {
    super(http, 'asset', OperatingSystem);
    this.setDefaultParam('asset_type', 'os');
  }

  getEntitiesResponse(root) {
    return root.get_assets.get_assets_response;
  }

  async get(params = {}, options) {
    if (!canUseNativeApi(this.http)) {
      return super.get(params, options);
    }

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

  async getAll(params = {}, options) {
    if (!canUseNativeApi(this.http)) {
      return super.getAll(params, options);
    }

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

  exportByIds(ids, assetType) {
    const data = {
      cmd: 'bulk_export',
      resource_type: this.name,
      assetType: assetType,
      bulk_select: BULK_SELECT_BY_IDS,
    };
    for (const id of ids) {
      data['bulk_selected:' + id] = 1;
    }
    return this.httpRequestWithRejectionTransform('post', {data});
  }

  export(entities, assetType) {
    return this.exportByIds(
      entities.map(element => {
        return element.id;
      }),
      assetType,
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
