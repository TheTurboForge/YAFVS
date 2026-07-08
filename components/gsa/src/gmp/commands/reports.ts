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
import {type XmlResponseData} from 'gmp/http/transform/fast-xml';
import Report from 'gmp/models/report';
import {
  fetchNativeReports,
  nativeReportQueryFromFilter,
} from 'gmp/native-api/reports';

class ReportsCommand extends EntitiesCommand<Report> {
  constructor(http: Http) {
    super(http, 'report', Report);
  }

  getEntitiesResponse(root: XmlResponseData): XmlResponseData {
    // @ts-expect-error
    return root.get_reports.get_reports_response;
  }

  async get(
    params: HttpCommandInputParams = {},
  ) {
    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeReports(
      this.http,
      nativeReportQueryFromFilter(filter),
    );
    return new Response(nativeResponse.reports, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(params: HttpCommandInputParams = {}) {
    const filter = filterFromCommandParams(params).all();
    const reports: Report[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; reports.length < total; page += 1) {
      const nativeResponse = await fetchNativeReports(this.http, {
        ...nativeReportQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      reports.push(...nativeResponse.reports);
      total = nativeResponse.page.total;
      if (nativeResponse.reports.length === 0) {
        break;
      }
    }

    return new Response(
      reports,
      nativeCollectionMeta(
        filter,
        reports,
        Number.isFinite(total) ? total : 0,
      ),
    );
  }
}

export default ReportsCommand;
