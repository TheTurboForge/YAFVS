/* SPDX-FileCopyrightText: 2026 Greenbone AG
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
import DfnCertAdv from 'gmp/models/dfn-cert';
import Filter from 'gmp/models/filter';
import {type Element} from 'gmp/models/model';
import {
  exportNativeDfnCertAdvisoriesMetadata,
  fetchNativeDfnCertAdvisories,
  nativeDfnCertAdvisoriesQueryFromFilter,
} from 'gmp/native-api/dfn-cert-advisories';
import {isDefined} from 'gmp/utils/identity';

const infoFilter = (info: Element) => isDefined(info.dfn_cert_adv);

const shouldExportAllByFilter = (filter: Filter): boolean => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

class DfnCertAdvisoriesCommand extends InfoEntitiesCommand<DfnCertAdv> {
  constructor(http: Http) {
    super(http, 'dfn_cert_adv', DfnCertAdv, infoFilter);
  }

  export(entities: DfnCertAdv[]) {
    return this.exportByIds(entities.map(entity => entity.id as string));
  }

  exportByIds(ids: string[]) {
    return exportNativeDfnCertAdvisoriesMetadata(this.http, ids);
  }

  async exportByFilter(filter: Filter) {
    const dfncerts: DfnCertAdv[] = [];
    if (shouldExportAllByFilter(filter)) {
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
    } else {
      const nativeResponse = await fetchNativeDfnCertAdvisories(
        this.http,
        nativeDfnCertAdvisoriesQueryFromFilter(filter),
      );
      dfncerts.push(...nativeResponse.dfncerts);
    }

    return exportNativeDfnCertAdvisoriesMetadata(
      this.http,
      dfncerts.map(advisory => advisory.id as string),
    );
  }

  async get(params: HttpCommandInputParams = {}) {
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
  ) {
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

}

export default DfnCertAdvisoriesCommand;
