/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntityCommand from 'gmp/commands/entity';
import {canUseNativeApi} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import {type XmlResponseData} from 'gmp/http/transform/fast-xml';
import logger from 'gmp/log';
import {filterString} from 'gmp/models/filter/utils';
import type {Element} from 'gmp/models/model';
import ReportFormat from 'gmp/models/report-format';
import {
  exportNativeReportFormatMetadata,
  fetchNativeReportFormat,
  patchNativeReportFormat,
} from 'gmp/native-api/report-formats';

interface ReportFormatResponseData extends XmlResponseData {
  get_report_format?: {
    get_report_formats_response?: {
      report_format?: Element;
    };
  };
}

const log = logger.getLogger('gmp.commands.reportformats');

const nativeReportFormatDetailSupportsFilter = (filter?: string): boolean =>
  filter === undefined || filterString(filter) === 'alerts=1';

export class ReportFormatCommand extends EntityCommand<ReportFormat> {
  constructor(http: Http) {
    super(http, 'report_format', ReportFormat);
  }

  import({xmlFile}: {xmlFile: string}) {
    const data = {
      cmd: 'import_report_format',
      xml_file: xmlFile,
    };
    log.debug('Importing report format', data);
    return this.action(data);
  }

  async export({id}: {id: string}) {
    return await exportNativeReportFormatMetadata(this.http, id);
  }

  async get(
    {id}: {id: string},
    {filter, ...options}: {filter?: string} = {},
  ) {
    if (canUseNativeApi(this.http) && nativeReportFormatDetailSupportsFilter(filter)) {
      return new Response(await fetchNativeReportFormat(this.http, id));
    }
    return super.get({id}, {filter, ...options});
  }

  async save(args: {active: boolean; id: string; name: string; summary: string}) {
    const {active, id, name, summary} = args;

    if (canUseNativeApi(this.http) && isReportFormatMetadataOnlySave(args)) {
      return patchNativeReportFormat(this.http, id, {active, name, summary});
    }

    const data = {
      cmd: 'save_report_format',
      enable: active,
      id,
      name,
      summary,
    };

    log.debug('Saving report format', args, data);
    return this.action(data);
  }

  getElementFromRoot(root: XmlResponseData) {
    return (
      (root as ReportFormatResponseData).get_report_format
        ?.get_report_formats_response?.report_format ?? {}
    );
  }
}

export default ReportFormatCommand;

const isReportFormatMetadataOnlySave = (args: object): boolean =>
  Object.keys(args).every(key =>
    ['active', 'id', 'name', 'summary'].includes(key),
  );
