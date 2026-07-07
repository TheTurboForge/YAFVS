/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntityCommand from 'gmp/commands/entity';
import {
  getMetricsNode,
  parseReportMetrics,
} from 'gmp/commands/report-metrics';
import type {ReportMetrics} from 'gmp/commands/report-metrics';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import {type XmlResponseData} from 'gmp/http/transform/fast-xml';
import logger from 'gmp/log';
import {type default as Filter, ALL_FILTER} from 'gmp/models/filter';
import {filterString} from 'gmp/models/filter/utils';
import Report, {type ReportElement} from 'gmp/models/report';
import {isDefined} from 'gmp/utils/identity';
import {fetchNativeReport} from 'gmp/native-api/reports';

interface ReportCommandAddAssetsParams {
  id: string;
  filter?: string;
}

interface ReportCommandARemoveAssetsParams {
  id: string;
  filter?: string;
}

interface ReportCommandAlertParams {
  alert_id: string;
  report_id: string;
  filter: string;
}

interface ReportCommandGetParams {
  id?: string;
  filter?: Filter;
  details?: boolean;
  ignorePagination?: boolean;
  lean?: boolean;
  options?: Record<string, unknown>;
}

interface ReportCommandDownloadParams {
  id: string;
}

interface ReportCommandDownloadOptions {
  reportFormatId: string;
  reportConfigId: string;
  filter?: Filter;
}

interface ReportCommandMetricsParams {
  id: string;
}

const log = logger.getLogger('gmp.commands.reports');

class ReportCommand extends EntityCommand<Report, ReportElement> {
  constructor(http: Http) {
    super(http, 'report', Report);
  }

  download(
    {id}: ReportCommandDownloadParams,
    {reportFormatId, reportConfigId, filter}: ReportCommandDownloadOptions,
  ) {
    const allFilter = isDefined(filter) ? filter.all() : ALL_FILTER;
    return this.httpRequestWithRejectionTransform<ArrayBuffer>('get', {
      args: {
        cmd: 'get_report',
        details: 1,
        report_id: id,
        report_config_id: reportConfigId,
        report_format_id: reportFormatId,
        filter: filterString(allFilter),
      },
      responseType: 'arraybuffer',
    });
  }

  addAssets({id, filter = ''}: ReportCommandAddAssetsParams) {
    return this.httpPostWithTransform({
      cmd: 'create_asset',
      report_id: id,
      filter,
    });
  }

  removeAssets({id, filter = ''}: ReportCommandARemoveAssetsParams) {
    return this.httpPostWithTransform({
      cmd: 'delete_asset',
      report_id: id,
      filter,
    });
  }

  // eslint-disable-next-line @typescript-eslint/naming-convention
  alert({alert_id, report_id, filter}: ReportCommandAlertParams) {
    return this.httpPostWithTransform({
      cmd: 'report_alert',
      alert_id,
      report_id,
      filter,
    });
  }

  async get(
    {id}: ReportCommandGetParams,
    {
      filter,
    }: ReportCommandGetParams = {},
  ) {
    if (id === undefined) {
      throw new Error('Report id is required for native report detail reads.');
    }
    const nativeResponse = await fetchNativeReport(this.http, id, filter);
    return new Response(nativeResponse.report);
  }

  async getMetrics({id}: ReportCommandMetricsParams) {
    const response = await this.httpGetWithTransform(
      {cmd: 'get_report_metrics', report_id: id},
      {includeDefaultParams: false},
    );
    const metrics = parseReportMetrics(
      getMetricsNode(response.data, 'get_report_metrics', 'report_metrics'),
    );
    return response.set<ReportMetrics>(metrics);
  }

  getElementFromRoot(root: XmlResponseData): ReportElement {
    // @ts-expect-error
    return root.get_report.get_reports_response.report;
  }
}

export default ReportCommand;
