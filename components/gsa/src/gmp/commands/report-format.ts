/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import HttpCommand from 'gmp/commands/http';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import {
  exportNativeReportFormatMetadata,
  fetchNativeReportFormat,
} from 'gmp/native-api/report-formats';

export class ReportFormatCommand extends HttpCommand {
  constructor(http: Http) {
    super(http);
  }

  async export({id}: {id: string}) {
    return await exportNativeReportFormatMetadata(this.http, id);
  }

  async get({id}: {id: string}, _options: {filter?: string} = {}) {
    return new Response(await fetchNativeReportFormat(this.http, id));
  }

}

export default ReportFormatCommand;
