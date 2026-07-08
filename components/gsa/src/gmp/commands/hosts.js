/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import registerCommand from 'gmp/command';
import EntitiesCommand from 'gmp/commands/entities';
import EntityCommand from 'gmp/commands/entity';
import {
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import Response from 'gmp/http/response';
import logger from 'gmp/log';
import Host from 'gmp/models/host';
import {
  exportNativeHostMetadata,
  exportNativeHostsMetadata,
  fetchNativeHosts,
  nativeHostsQueryFromFilter,
} from 'gmp/native-api/hosts';

const log = logger.getLogger('gmp.commands.hosts');

const shouldExportAllByFilter = filter => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

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

  async get(params = {}, _options) {
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

  async getAll(params = {}, _options) {
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

  exportByIds(ids, _assetType) {
    return exportNativeHostsMetadata(this.http, ids);
  }

  export(entities, _assetType) {
    return this.exportByIds(entities.map(element => element.id));
  }

  async exportByFilter(filter) {
    const hosts = [];
    if (shouldExportAllByFilter(filter)) {
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
    } else {
      const nativeResponse = await fetchNativeHosts(
        this.http,
        nativeHostsQueryFromFilter(filter),
      );
      hosts.push(...nativeResponse.hosts);
    }

    return exportNativeHostsMetadata(
      this.http,
      hosts.map(host => host.id),
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
