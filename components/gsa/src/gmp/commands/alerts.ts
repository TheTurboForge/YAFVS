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
import Alert from 'gmp/models/alert';
import Filter from 'gmp/models/filter';
import {type Element} from 'gmp/models/model';
import {
  exportNativeAlertsMetadata,
  fetchNativeAlerts,
  nativeAlertsQueryFromFilter,
} from 'gmp/native-api/alerts';

const shouldExportAllByFilter = (filter: Filter): boolean => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

class AlertsCommand extends EntitiesCommand<Alert> {
  constructor(http: Http) {
    super(http, 'alert', Alert);
  }

  export(entities: Alert[]) {
    if (!canUseNativeApi(this.http)) {
      return super.export(entities);
    }

    return this.exportByIds(entities.map(entity => entity.id as string));
  }

  exportByIds(ids: string[]) {
    if (!canUseNativeApi(this.http)) {
      return super.exportByIds(ids);
    }

    return exportNativeAlertsMetadata(this.http, ids);
  }

  async exportByFilter(filter: Filter) {
    if (!canUseNativeApi(this.http)) {
      return super.exportByFilter(filter);
    }

    const alerts: Alert[] = [];
    if (shouldExportAllByFilter(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; alerts.length < total; page += 1) {
        const nativeResponse = await fetchNativeAlerts(this.http, {
          ...nativeAlertsQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        alerts.push(...nativeResponse.alerts);
        total = nativeResponse.page.total;
        if (nativeResponse.alerts.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativeAlerts(
        this.http,
        nativeAlertsQueryFromFilter(filter),
      );
      alerts.push(...nativeResponse.alerts);
    }

    return exportNativeAlertsMetadata(
      this.http,
      alerts.map(alert => alert.id as string),
    );
  }

  getEntitiesResponse(root: Element): Element {
    // @ts-expect-error
    return root.get_alerts.get_alerts_response;
  }

  async get(params: HttpCommandInputParams = {}, options?: HttpCommandOptions) {
    if (!canUseNativeApi(this.http)) {
      return super.get(params, options);
    }

    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeAlerts(
      this.http,
      nativeAlertsQueryFromFilter(filter),
    );
    return new Response(nativeResponse.alerts, {
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
    const alerts: Alert[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; alerts.length < total; page += 1) {
      const nativeResponse = await fetchNativeAlerts(this.http, {
        ...nativeAlertsQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      alerts.push(...nativeResponse.alerts);
      total = nativeResponse.page.total;
      if (nativeResponse.alerts.length === 0) {
        break;
      }
    }

    return new Response(
      alerts,
      nativeCollectionMeta(filter, alerts, Number.isFinite(total) ? total : 0),
    );
  }
}

export default AlertsCommand;
