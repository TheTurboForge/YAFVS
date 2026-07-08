/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntitiesCommand from 'gmp/commands/entities';
import type {HttpCommandInputParams} from 'gmp/commands/http';
import {
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import Scanner from 'gmp/models/scanner';
import {
  fetchNativeScanners,
  exportNativeScannersMetadata,
  nativeScannersQueryFromFilter,
} from 'gmp/native-api/scanners';

const shouldExportAllByFilter = filter => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

class ScannersCommand extends EntitiesCommand<Scanner> {
  constructor(http: Http) {
    super(http, 'scanner', Scanner);
  }

  getEntitiesResponse(root) {
    return root.get_scanners.get_scanners_response;
  }

  async get(params: HttpCommandInputParams = {}) {
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

  async getAll(params: HttpCommandInputParams = {}) {
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

  exportByIds(ids: string[]) {
    return exportNativeScannersMetadata(this.http, ids);
  }

  export(entities: Scanner[]) {
    return this.exportByIds(
      entities.flatMap(entity =>
        entity.id === undefined ? [] : [entity.id],
      ),
    );
  }

  async exportByFilter(filter) {
    const scanners: Scanner[] = [];
    if (shouldExportAllByFilter(filter)) {
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
    } else {
      const nativeResponse = await fetchNativeScanners(
        this.http,
        nativeScannersQueryFromFilter(filter),
      );
      scanners.push(...nativeResponse.scanners);
    }

    return exportNativeScannersMetadata(
      this.http,
      scanners.flatMap(scanner =>
        scanner.id === undefined ? [] : [scanner.id],
      ),
    );
  }
}

export default ScannersCommand;
