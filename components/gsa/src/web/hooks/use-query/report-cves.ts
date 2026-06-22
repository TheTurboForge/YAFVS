/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import {type EntitiesMeta} from 'gmp/commands/entities';
import Response from 'gmp/http/response';
import Filter from 'gmp/models/filter';
import {isFilter} from 'gmp/models/filter/utils';
import {type ReportActiveCve} from 'gmp/models/report/parser';
import {
  fetchNativeReportCves,
  nativeReportCvesQueryFromFilter,
} from 'gmp/native-api/reports';
import useGmp from 'web/hooks/useGmp';
import useGetEntities from 'web/queries/useGetEntities';

interface UseGetReportCvesParams {
  reportId: string;
  filter?: Filter;
  refetchInterval?: number | false;
}

const canUseNativeApi = (gmp: {buildUrl?: unknown}) =>
  typeof gmp?.buildUrl === 'function';

const nativeCountResponse = (
  total: number,
  filter?: Filter,
): Response<ReportActiveCve[], EntitiesMeta> => {
  return new Response<ReportActiveCve[], EntitiesMeta>([], {
    filter: filter ?? new Filter(),
    counts: new CollectionCounts({
      all: total,
      filtered: total,
      first: total > 0 ? 1 : 0,
      length: total > 0 ? 1 : 0,
      rows: 1,
    }),
  });
};

export const useGetReportCves = ({
  reportId,
  filter = undefined,
  refetchInterval = false,
}: UseGetReportCvesParams) => {
  const gmp = useGmp();

  return useGetEntities({
    gmpMethod: async ({filter: reportFilter}) => {
      if (!canUseNativeApi(gmp)) {
        return gmp.reportcves.get({
          report_id: reportId,
          filter: reportFilter,
        });
      }

      const nativeFilter = isFilter(reportFilter) ? reportFilter : filter;
      const nativeQuery = nativeReportCvesQueryFromFilter(nativeFilter);
      const response = await fetchNativeReportCves(gmp, reportId, {
        ...nativeQuery,
        page: 1,
        pageSize: 1,
        sort: '-max_severity',
      });
      return nativeCountResponse(response.page.total, nativeFilter);
    },
    queryId: `get_report_cves_${reportId}`,
    filter,
    refetchInterval,
    enabled: Boolean(reportId),
    keepPreviousData: true,
  });
};

export default useGetReportCves;
