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
import Vulnerability from 'gmp/models/vulnerability';
import {
  exportNativeVulnerabilityMetadata,
  fetchNativeVulnerabilities,
  nativeVulnerabilitiesQueryFromFilter,
} from 'gmp/native-api/vulnerabilities';

class VulnerabilityCommand extends EntityCommand {
  constructor(http) {
    super(http, 'vuln', Vulnerability);
  }

  async export({id}) {
    return await exportNativeVulnerabilityMetadata(this.http, id);
  }
}

class VulnerabilitiesCommand extends EntitiesCommand {
  constructor(http) {
    super(http, 'vuln', Vulnerability);
  }

  getEntitiesResponse(root) {
    return root.get_vulns.get_vulns_response;
  }

  async get(params = {}) {
    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeVulnerabilities(
      this.http,
      nativeVulnerabilitiesQueryFromFilter(filter),
    );
    return new Response(nativeResponse.vulnerabilities, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(params = {}) {
    const filter = filterFromCommandParams(params).all();
    const vulnerabilities = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; vulnerabilities.length < total; page += 1) {
      const nativeResponse = await fetchNativeVulnerabilities(this.http, {
        ...nativeVulnerabilitiesQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      vulnerabilities.push(...nativeResponse.vulnerabilities);
      total = nativeResponse.page.total;
      if (nativeResponse.vulnerabilities.length === 0) {
        break;
      }
    }

    return new Response(
      vulnerabilities,
      nativeCollectionMeta(
        filter,
        vulnerabilities,
        Number.isFinite(total) ? total : 0,
      ),
    );
  }

  getSeverityAggregates({filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'vuln',
      group_column: 'severity',
      filter,
    });
  }

  getHostAggregates({filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'vuln',
      group_column: 'hosts',
      filter,
    });
  }
}

registerCommand('vuln', VulnerabilityCommand);
registerCommand('vulns', VulnerabilitiesCommand);

export {VulnerabilityCommand, VulnerabilitiesCommand};
