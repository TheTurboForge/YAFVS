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
import {
  fetchNativeReportTlsCertificates,
  nativeReportTlsCertificatesQueryFromFilter,
  type NativeReportTlsCertificateItem,
} from 'gmp/native-api/reports';
import useGmp from 'web/hooks/useGmp';
import useGetEntities from 'web/queries/useGetEntities';

interface UseGetReportTlsCertificatesParams {
  reportId: string;
  filter?: Filter;
  refetchInterval?: number | false;
}

const nativeCountResponse = (
  total: number,
  filter?: Filter,
): Response<NativeReportTlsCertificateItem[], EntitiesMeta> => {
  return new Response<NativeReportTlsCertificateItem[], EntitiesMeta>([], {
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

export const useGetReportTlsCertificates = ({
  reportId,
  filter = undefined,
  refetchInterval = undefined,
}: UseGetReportTlsCertificatesParams) => {
  const gmp = useGmp();

  return useGetEntities<NativeReportTlsCertificateItem>({
    gmpMethod: async ({filter: reportFilter}) => {
      const nativeFilter = isFilter(reportFilter) ? reportFilter : filter;
      const nativeQuery =
        nativeReportTlsCertificatesQueryFromFilter(nativeFilter);
      const response = await fetchNativeReportTlsCertificates(gmp, reportId, {
        ...nativeQuery,
        page: 1,
        pageSize: 1,
        sort: '-not_after',
      });
      return nativeCountResponse(response.page.total, nativeFilter);
    },
    queryId: `native_report_tls_certificates_${reportId}`,
    filter,
    enabled: Boolean(reportId),
    keepPreviousData: true,
    refetchInterval,
  });
};

export default useGetReportTlsCertificates;
