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
import type Filter from 'gmp/models/filter';
import type {Element} from 'gmp/models/model';
import ReportFormat from 'gmp/models/report-format';
import {
  exportNativeReportFormatsMetadata,
  fetchNativeReportFormats,
  nativeReportFormatsQueryFromFilter,
} from 'gmp/native-api/report-formats';

const shouldExportAllByFilter = (filter: Filter): boolean => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

export class ReportFormatsCommand extends EntitiesCommand<ReportFormat> {
  constructor(http: Http) {
    super(http, 'report_format', ReportFormat);
  }

  getEntitiesResponse(): Element {
    return {};
  }

  export(entities: ReportFormat[]) {
    return this.exportByIds(entities.map(entity => entity.id as string));
  }

  exportByIds(ids: string[]) {
    return exportNativeReportFormatsMetadata(this.http, ids);
  }

  async exportByFilter(filter: Filter) {
    const reportFormats: ReportFormat[] = [];
    if (shouldExportAllByFilter(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; reportFormats.length < total; page += 1) {
        const nativeResponse = await fetchNativeReportFormats(this.http, {
          ...nativeReportFormatsQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        reportFormats.push(...nativeResponse.reportFormats);
        total = nativeResponse.page.total;
        if (nativeResponse.reportFormats.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativeReportFormats(
        this.http,
        nativeReportFormatsQueryFromFilter(filter),
      );
      reportFormats.push(...nativeResponse.reportFormats);
    }

    return exportNativeReportFormatsMetadata(
      this.http,
      reportFormats.map(reportFormat => reportFormat.id as string),
    );
  }

  async get(params: HttpCommandInputParams = {}) {
    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeReportFormats(
      this.http,
      nativeReportFormatsQueryFromFilter(filter),
    );
    return new Response(nativeResponse.reportFormats, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(
    params: HttpCommandInputParams = {},
  ) {
    const filter = filterFromCommandParams(params).all();
    const reportFormats: ReportFormat[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; reportFormats.length < total; page += 1) {
      const nativeResponse = await fetchNativeReportFormats(this.http, {
        ...nativeReportFormatsQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      reportFormats.push(...nativeResponse.reportFormats);
      total = nativeResponse.page.total;
      if (nativeResponse.reportFormats.length === 0) {
        break;
      }
    }

    return new Response(
      reportFormats,
      nativeCollectionMeta(
        filter,
        reportFormats,
        Number.isFinite(total) ? total : 0,
      ),
    );
  }
}

export default ReportFormatsCommand;
