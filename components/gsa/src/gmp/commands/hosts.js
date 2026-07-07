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
import logger from 'gmp/log';
import Host from 'gmp/models/host';
import {
  exportNativeHostMetadata,
  fetchNativeHosts,
  nativeHostsQueryFromFilter,
} from 'gmp/native-api/hosts';

const log = logger.getLogger('gmp.commands.hosts');

class HostCommand extends EntityCommand {
  constructor(http) {
    super(http, 'asset', Host);
    this.setDefaultParam('asset_type', 'host');
  }

  create(args) {
    const {name, comment = ''} = args;
    log.debug('Creating host', args);
    return this.action({
      cmd: 'create_host',
      name,
      comment,
    });
  }

  save(args) {
    const {id, comment = ''} = args;
    log.debug('Saving host', args);
    return this.action({
      cmd: 'save_asset',
      asset_id: id,
      comment,
    });
  }

  deleteIdentifier({id}) {
    log.debug('Deleting Host Identifier with id', id);
    return this.httpPostWithTransform({
      cmd: 'delete_asset',
      asset_id: id,
    });
  }

  async export({id}) {
    return await exportNativeHostMetadata(this.http, id);
  }

  getElementFromRoot(root) {
    return root.get_asset.get_assets_response.asset;
  }
}

class HostsCommand extends EntitiesCommand {
  constructor(http) {
    super(http, 'asset', Host);
    this.setDefaultParam('asset_type', 'host');
  }

  getEntitiesResponse(root) {
    return root.get_assets.get_assets_response;
  }

  async get(params = {}, options) {
    if (!canUseNativeApi(this.http)) {
      return super.get(params, options);
    }

    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeHosts(
      this.http,
      nativeHostsQueryFromFilter(filter),
    );
    return new Response(nativeResponse.hosts, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(params = {}, options) {
    if (!canUseNativeApi(this.http)) {
      return super.getAll(params, options);
    }

    const filter = filterFromCommandParams(params).all();
    const hosts = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; hosts.length < total; page += 1) {
      const nativeResponse = await fetchNativeHosts(this.http, {
        ...nativeHostsQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      hosts.push(...nativeResponse.hosts);
      total = nativeResponse.page.total;
      if (nativeResponse.hosts.length === 0) {
        break;
      }
    }

    return new Response(
      hosts,
      nativeCollectionMeta(filter, hosts, Number.isFinite(total) ? total : 0),
    );
  }

  getModifiedAggregates({filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'host',
      group_column: 'modified',
      subgroup_column: 'severity_level',
      filter,
    });
  }

  getSeverityAggregates({filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'host',
      group_column: 'severity',
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
      aggregate_type: 'host',
      group_column: 'uuid',
      textColumns: ['name', 'modified'],
      dataColumns: ['severity'],
      sort: [
        {
          field: 'severity',
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

registerCommand('host', HostCommand);
registerCommand('hosts', HostsCommand);

export {HostCommand, HostsCommand};
