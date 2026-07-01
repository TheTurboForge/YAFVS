/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntitiesCommand from 'gmp/commands/entities';
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
import Scanner from 'gmp/models/scanner';
import {
  fetchNativeScanners,
  nativeScannersQueryFromFilter,
} from 'gmp/native-api/scanners';

class ScannersCommand extends EntitiesCommand<Scanner> {
  constructor(http: Http) {
    super(http, 'scanner', Scanner);
  }

  getEntitiesResponse(root) {
    return root.get_scanners.get_scanners_response;
  }

  async get(params: HttpCommandInputParams = {}, options?: HttpCommandOptions) {
    if (!canUseNativeApi(this.http)) {
      return super.get(params, options);
    }

    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeScanners(
      this.http,
      nativeScannersQueryFromFilter(filter),
    );
    return new Response(nativeResponse.scanners, {
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
    const scanners: Scanner[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; scanners.length < total; page += 1) {
      const nativeResponse = await fetchNativeScanners(this.http, {
        ...nativeScannersQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      scanners.push(...nativeResponse.scanners);
      total = nativeResponse.page.total;
      if (nativeResponse.scanners.length === 0) {
        break;
      }
    }

    return new Response(
      scanners,
      nativeCollectionMeta(
        filter,
        scanners,
        Number.isFinite(total) ? total : 0,
      ),
    );
  }
}

export default ScannersCommand;
