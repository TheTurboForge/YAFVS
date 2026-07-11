/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import HttpCommand from 'gmp/commands/http';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import type Filter from 'gmp/models/filter';
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

class ReportCommand extends HttpCommand {
  constructor(http: Http) {
    super(http);
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
