/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntitiesCommand from 'gmp/commands/entities';
import {
  type HttpCommandInputParams,
  type HttpCommandOptions,
} from 'gmp/commands/http';
import {
  canUseNativeApi,
  filterFromCommandParams,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import {type Element} from 'gmp/models/model';
import Result from 'gmp/models/result';
import {
  fetchNativeResults,
  nativeReportResultsQueryFromFilter,
} from 'gmp/native-api/reports';
import {exportNativeResultsMetadata} from 'gmp/native-api/results';

const shouldExportAllByFilter = filter => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

const explicitlyRequestsSummaryOnly = (details: unknown): boolean =>
  details === false || details === 0 || details === '0';

export class ResultsCommand extends EntitiesCommand<Result> {
  constructor(http: Http) {
    super(http, 'result', Result);
  }

  getEntitiesResponse(root: Element): Element {
    // @ts-expect-error
    return root.get_results.get_results_response;
  }

  async get(params: HttpCommandInputParams = {}, options?: HttpCommandOptions) {
    if (canUseNativeApi(this.http) && !explicitlyRequestsSummaryOnly(params.details)) {
      const filter = filterFromCommandParams(params);
      const nativeResponse = await fetchNativeResults(
        this.http,
        nativeReportResultsQueryFromFilter(filter),
      );
      return new Response(nativeResponse.results, {
        filter,
        counts: nativeResponse.counts,
      });
    }
    return super.get({details: 1, ...params}, options);
  }

  exportByIds(ids: string[]) {
    return exportNativeResultsMetadata(this.http, ids);
  }

  export(entities: Result[]) {
    return this.exportByIds(
      entities.flatMap(entity =>
        entity.id === undefined ? [] : [entity.id],
      ),
    );
  }

  async exportByFilter(filter) {
    const results: Result[] = [];
    if (shouldExportAllByFilter(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; results.length < total; page += 1) {
        const nativeResponse = await fetchNativeResults(this.http, {
          ...nativeReportResultsQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        results.push(...nativeResponse.results);
        total = nativeResponse.page.total;
        if (nativeResponse.results.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativeResults(
        this.http,
        nativeReportResultsQueryFromFilter(filter),
      );
      results.push(...nativeResponse.results);
    }

    return exportNativeResultsMetadata(
      this.http,
      results.flatMap(result =>
        result.id === undefined ? [] : [result.id],
      ),
    );
  }

}
