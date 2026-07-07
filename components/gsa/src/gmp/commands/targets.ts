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
import {type Element} from 'gmp/models/model';
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

class TargetsCommand extends EntitiesCommand<Target> {
  constructor(http: Http) {
    super(http, 'target', Target);
  }

  getEntitiesResponse(root: Element): Element {
    // @ts-expect-error
    return root.get_targets.get_targets_response;
  }

  async get(params: HttpCommandInputParams = {}, options?: HttpCommandOptions) {
    if (!canUseNativeApi(this.http)) {
      return super.get(params, options);
    }

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

  async getAll(
    params: HttpCommandInputParams = {},
    options?: HttpCommandOptions,
  ) {
    if (!canUseNativeApi(this.http)) {
      return super.getAll(params, options);
    }

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
      nativeCollectionMeta(
        filter,
        targets,
        Number.isFinite(total) ? total : 0,
      ),
    );
  }

  exportByIds(ids: string[]) {
    return exportNativeTargetsMetadata(this.http, ids);
  }

  export(entities: Target[]) {
    return this.exportByIds(
      entities.flatMap(entity =>
        entity.id === undefined ? [] : [entity.id],
      ),
    );
  }

  async exportByFilter(filter) {
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
      targets.flatMap(target =>
        target.id === undefined ? [] : [target.id],
      ),
    );
  }
}

export default TargetsCommand;
