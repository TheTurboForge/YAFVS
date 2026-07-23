/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntitiesCommand from 'gmp/commands/entities';
import type {HttpCommandInputParams} from 'gmp/commands/http';
import {
  canUseNativeApi,
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import Target from 'gmp/models/target';
import {
  exportNativeTargetsMetadata,
  fetchNativeTargets,
  nativeTargetQueryFromFilter,
} from 'gmp/native-api/targets';

const shouldExportAllByFilter = filter => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

const requireNativeTargetApi = (http: Http) => {
  if (!canUseNativeApi(http)) {
    throw new Error('Native target API is required for targets command');
  }
};

class TargetsCommand extends EntitiesCommand<Target> {
  constructor(http: Http) {
    super(http, 'target', Target);
  }

  protected getEntitiesResponse(): never {
    throw new Error('Target XML collection parsing has been retired');
  }

  async get(params: HttpCommandInputParams = {}) {
    requireNativeTargetApi(this.http);
    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeTargets(
      this.http,
      nativeTargetQueryFromFilter(filter),
    );
    return new Response(nativeResponse.targets, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(params: HttpCommandInputParams = {}) {
    requireNativeTargetApi(this.http);
    const filter = filterFromCommandParams(params).all();
    const targets: Target[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; targets.length < total; page += 1) {
      const nativeResponse = await fetchNativeTargets(this.http, {
        ...nativeTargetQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      targets.push(...nativeResponse.targets);
      total = nativeResponse.page.total;
      if (nativeResponse.targets.length === 0) {
        break;
      }
    }

    return new Response(
      targets,
      nativeCollectionMeta(filter, targets, Number.isFinite(total) ? total : 0),
    );
  }

  exportByIds(ids: string[]) {
    requireNativeTargetApi(this.http);
    return exportNativeTargetsMetadata(this.http, ids);
  }

  export(entities: Target[]) {
    return this.exportByIds(
      entities.flatMap(entity => (entity.id === undefined ? [] : [entity.id])),
    );
  }

  async exportByFilter(filter) {
    requireNativeTargetApi(this.http);
    const targets: Target[] = [];
    if (shouldExportAllByFilter(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; targets.length < total; page += 1) {
        const nativeResponse = await fetchNativeTargets(this.http, {
          ...nativeTargetQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        targets.push(...nativeResponse.targets);
        total = nativeResponse.page.total;
        if (nativeResponse.targets.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativeTargets(
        this.http,
        nativeTargetQueryFromFilter(filter),
      );
      targets.push(...nativeResponse.targets);
    }

    return exportNativeTargetsMetadata(
      this.http,
      targets.flatMap(target => (target.id === undefined ? [] : [target.id])),
    );
  }
}

export default TargetsCommand;
