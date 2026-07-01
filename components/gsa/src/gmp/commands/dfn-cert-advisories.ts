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
import DfnCertAdv from 'gmp/models/dfn-cert';
import type Filter from 'gmp/models/filter';
import {type Element} from 'gmp/models/model';
import {
  fetchNativeDfnCertAdvisories,
  nativeDfnCertAdvisoriesQueryFromFilter,
} from 'gmp/native-api/dfn-cert-advisories';
import {isDefined} from 'gmp/utils/identity';

const infoFilter = (info: Element) => isDefined(info.dfn_cert_adv);

class DfnCertAdvisoriesCommand extends InfoEntitiesCommand<DfnCertAdv> {
  constructor(http: Http) {
    super(http, 'dfn_cert_adv', DfnCertAdv, infoFilter);
  }

  async get(params: HttpCommandInputParams = {}, options?: HttpCommandOptions) {
    if (!canUseNativeApi(this.http)) {
      return super.get(params, options);
    }

    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeDfnCertAdvisories(
      this.http,
      nativeDfnCertAdvisoriesQueryFromFilter(filter),
    );
    return new Response(nativeResponse.dfncerts, {
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
    const dfncerts: DfnCertAdv[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; dfncerts.length < total; page += 1) {
      const nativeResponse = await fetchNativeDfnCertAdvisories(this.http, {
        ...nativeDfnCertAdvisoriesQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      dfncerts.push(...nativeResponse.dfncerts);
      total = nativeResponse.page.total;
      if (nativeResponse.dfncerts.length === 0) {
        break;
      }
    }

    return new Response(
      dfncerts,
      nativeCollectionMeta(
        filter,
        dfncerts,
        Number.isFinite(total) ? total : 0,
      ),
    );
  }

  getCreatedAggregates({filter}: {filter?: Filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'dfn_cert_adv',
      group_column: 'created',
      filter,
    });
  }

  getSeverityAggregates({filter}: {filter?: Filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'dfn_cert_adv',
      group_column: 'severity',
      filter,
    });
  }
}

export default DfnCertAdvisoriesCommand;
