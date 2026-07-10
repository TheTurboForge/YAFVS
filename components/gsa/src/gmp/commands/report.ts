/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import HttpCommand from 'gmp/commands/http';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import {type default as Filter, ALL_FILTER} from 'gmp/models/filter';
import {filterString} from 'gmp/models/filter/utils';
import {fetchNativeReport} from 'gmp/native-api/reports';
import {isDefined} from 'gmp/utils/identity';

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

class ReportCommand extends HttpCommand {
  constructor(http: Http) {
    super(http);
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
    {filter}: ReportCommandGetParams = {},
  ) {
    if (id === undefined) {
      throw new Error('Report id is required for native report detail reads.');
    }
    const nativeResponse = await fetchNativeReport(this.http, id, filter);
    return new Response(nativeResponse.report);
  }
}

export default ReportCommand;
