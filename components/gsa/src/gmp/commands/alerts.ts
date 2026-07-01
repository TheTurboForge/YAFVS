/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import EntitiesCommand from 'gmp/commands/entities';
import type {
  HttpCommandInputParams,
  HttpCommandOptions,
} from 'gmp/commands/http';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import Alert from 'gmp/models/alert';
import Filter from 'gmp/models/filter';
import {type Element} from 'gmp/models/model';
import {
  fetchNativeAlerts,
  nativeAlertsQueryFromFilter,
} from 'gmp/native-api/alerts';
import {isString} from 'gmp/utils/identity';

const NATIVE_ALERT_COMMAND_PAGE_SIZE = 500;

const canUseNativeApi = (http: {buildUrl?: unknown}) =>
  typeof http?.buildUrl === 'function';

const filterFromParams = (params: HttpCommandInputParams = {}) => {
  const {filter} = params;
  if (filter instanceof Filter) {
    return filter;
  }
  if (isString(filter)) {
    return Filter.fromString(filter);
  }
  return new Filter();
};

const nativeMeta = (filter: Filter, alerts: Alert[], total: number) => ({
  filter,
  counts: new CollectionCounts({
    first: total > 0 ? 1 : 0,
    all: total,
    filtered: total,
    length: alerts.length,
    rows: alerts.length,
  }),
});

class AlertsCommand extends EntitiesCommand<Alert> {
  constructor(http: Http) {
    super(http, 'alert', Alert);
  }

  getEntitiesResponse(root: Element): Element {
    // @ts-expect-error
    return root.get_alerts.get_alerts_response;
  }

  async get(params: HttpCommandInputParams = {}, options?: HttpCommandOptions) {
    if (!canUseNativeApi(this.http)) {
      return super.get(params, options);
    }

    const filter = filterFromParams(params);
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

    const filter = filterFromParams(params).all();
    const alerts: Alert[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; alerts.length < total; page += 1) {
      const nativeResponse = await fetchNativeAlerts(this.http, {
        ...nativeAlertsQueryFromFilter(filter),
        page,
        pageSize: NATIVE_ALERT_COMMAND_PAGE_SIZE,
      });
      alerts.push(...nativeResponse.alerts);
      total = nativeResponse.page.total;
      if (nativeResponse.alerts.length === 0) {
        break;
      }
    }

    return new Response(
      alerts,
      nativeMeta(filter, alerts, Number.isFinite(total) ? total : 0),
    );
  }
}

export default AlertsCommand;
