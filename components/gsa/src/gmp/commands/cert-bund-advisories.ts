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
import CertBundAdv from 'gmp/models/cert-bund';
import type Filter from 'gmp/models/filter';
import {type Element} from 'gmp/models/model';
import {
  fetchNativeCertBundAdvisories,
  nativeCertBundAdvisoriesQueryFromFilter,
} from 'gmp/native-api/cert-bund-advisories';
import {isDefined} from 'gmp/utils/identity';

const infoFilter = (info: Element) => isDefined(info.cert_bund_adv);

class CertBundAdvisoriesCommand extends InfoEntitiesCommand<CertBundAdv> {
  constructor(http: Http) {
    super(http, 'cert_bund_adv', CertBundAdv, infoFilter);
  }

  async get(params: HttpCommandInputParams = {}, options?: HttpCommandOptions) {
    if (!canUseNativeApi(this.http)) {
      return super.get(params, options);
    }

    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeCertBundAdvisories(
      this.http,
      nativeCertBundAdvisoriesQueryFromFilter(filter),
    );
    return new Response(nativeResponse.certbunds, {
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
    const certbunds: CertBundAdv[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; certbunds.length < total; page += 1) {
      const nativeResponse = await fetchNativeCertBundAdvisories(this.http, {
        ...nativeCertBundAdvisoriesQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      certbunds.push(...nativeResponse.certbunds);
      total = nativeResponse.page.total;
      if (nativeResponse.certbunds.length === 0) {
        break;
      }
    }

    return new Response(
      certbunds,
      nativeCollectionMeta(
        filter,
        certbunds,
        Number.isFinite(total) ? total : 0,
      ),
    );
  }

  getCreatedAggregates({filter}: {filter?: Filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'cert_bund_adv',
      group_column: 'created',
      filter,
    });
  }

  getSeverityAggregates({filter}: {filter?: Filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'cert_bund_adv',
      group_column: 'severity',
      filter,
    });
  }
}

export default CertBundAdvisoriesCommand;
