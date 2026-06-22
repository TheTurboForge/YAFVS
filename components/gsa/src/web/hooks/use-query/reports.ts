/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useQuery} from '@tanstack/react-query';
import CollectionCounts from 'gmp/collection/collection-counts';
import type {EntitiesMeta} from 'gmp/commands/entities';
import Response from 'gmp/http/response';
import type {XmlMeta} from 'gmp/http/transform/fast-xml';
import Filter, {ALL_FILTER, RESULTS_FILTER_FILTER} from 'gmp/models/filter';
import type Report from 'gmp/models/report';
import type ReportConfig from 'gmp/models/report-config';
import type ReportFormat from 'gmp/models/report-format';
import {
  fetchNativeFilters,
  nativeFiltersQueryFromFilter,
} from 'gmp/native-api/filters';
import {fetchNativeReportConfigs} from 'gmp/native-api/report-configs';
import {fetchNativeReportFormats} from 'gmp/native-api/report-formats';
import {fetchNativeReport} from 'gmp/native-api/reports';
import {isDefined} from 'gmp/utils/identity';
import useGmp from 'web/hooks/useGmp';
import useSessionToken from 'web/hooks/useSessionToken';
import {type RefetchIntervalFn} from 'web/queries/helpers';
import useGetEntities from 'web/queries/useGetEntities';
import useGetEntity from 'web/queries/useGetEntity';

interface UseGetReportParams {
  id: string;
  filter?: Filter;
  refetchInterval?: number | false | RefetchIntervalFn<Report>;
}

const REPORT_FORMATS_FILTER = Filter.fromString('active=1 and trust=1 rows=-1');
const REPORT_DROPDOWN_PAGE_SIZE = 500;

const nativeDropdownQuery = (page: number) => ({
  page,
  pageSize: REPORT_DROPDOWN_PAGE_SIZE,
  sort: 'name',
  filter: '',
});

const nativeDropdownCounts = (length: number) =>
  new CollectionCounts({
    first: length > 0 ? 1 : 0,
    all: length,
    filtered: length,
    length,
    rows: length,
  });

const nativeDropdownResponse = <TModel>(entities: TModel[], filter: Filter) =>
  new Response<TModel[], EntitiesMeta>(entities, {
    counts: nativeDropdownCounts(entities.length),
    filter,
  });

const fetchAllNativeReportFormatsForDropdown = async (
  gmp: Parameters<typeof fetchNativeReportFormats>[0],
): Promise<ReportFormat[]> => {
  const reportFormats: ReportFormat[] = [];

  // Preserve the inherited active/trusted dropdown predicate until the native
  // endpoint grows equivalent structured filters.
  for (let page = 1; ; page += 1) {
    const response = await fetchNativeReportFormats(
      gmp,
      nativeDropdownQuery(page),
    );
    reportFormats.push(...response.reportFormats);

    if (
      response.reportFormats.length === 0 ||
      reportFormats.length >= response.page.total
    ) {
      break;
    }
  }

  return reportFormats.filter(
    format => format.isActive() && format.isTrusted(),
  );
};

const fetchAllNativeReportConfigsForDropdown = async (
  gmp: Parameters<typeof fetchNativeReportConfigs>[0],
): Promise<ReportConfig[]> => {
  const reportConfigs: ReportConfig[] = [];

  for (let page = 1; ; page += 1) {
    const response = await fetchNativeReportConfigs(
      gmp,
      nativeDropdownQuery(page),
    );
    reportConfigs.push(...response.reportConfigs);

    if (
      response.reportConfigs.length === 0 ||
      reportConfigs.length >= response.page.total
    ) {
      break;
    }
  }

  return reportConfigs;
};

export const useGetReport = ({
  id,
  filter,
  refetchInterval,
}: UseGetReportParams) => {
  const gmp = useGmp();
  const filterString = filter?.toFilterString();

  return useGetEntity<Report>({
    gmpMethod: async ({id}) => {
      const nativeResponse = await fetchNativeReport(gmp, id, filter);
      return {data: nativeResponse.report} as Response<Report, XmlMeta>;
    },
    queryId: 'get_report',
    queryKeyParts: [filterString],
    id,
    refetchInterval,
  });
};

export const useGetResultsFilters = () => {
  const gmp = useGmp();
  const canUseNativeApi = typeof gmp?.buildUrl === 'function';

  return useGetEntities<Filter>({
    gmpMethod: async ({filter}) => {
      const queryFilter = filter instanceof Filter ? filter : undefined;

      if (!canUseNativeApi) {
        return gmp.filters.get({filter: queryFilter});
      }

      const response = await fetchNativeFilters(
        gmp,
        nativeFiltersQueryFromFilter(queryFilter),
      );
      return new Response<Filter[], EntitiesMeta>(response.filters, {
        counts: response.counts,
        filter: queryFilter ?? RESULTS_FILTER_FILTER,
      });
    },
    queryId: 'get_filters',
    filter: RESULTS_FILTER_FILTER,
    refetchInterval: false,
    keepPreviousData: true,
  });
};

export const useGetReportFormats = () => {
  const gmp = useGmp();
  const canUseNativeApi = typeof gmp?.buildUrl === 'function';

  return useGetEntities<ReportFormat>({
    gmpMethod: async ({filter}) => {
      const queryFilter =
        filter instanceof Filter ? filter : REPORT_FORMATS_FILTER;

      if (!canUseNativeApi) {
        return gmp.reportformats.get({filter: queryFilter});
      }

      const reportFormats = await fetchAllNativeReportFormatsForDropdown(gmp);
      return nativeDropdownResponse(reportFormats, queryFilter);
    },
    queryId: 'get_report_formats',
    filter: REPORT_FORMATS_FILTER,
    refetchInterval: false,
    keepPreviousData: true,
  });
};

export const useGetReportConfigs = () => {
  const gmp = useGmp();
  const canUseNativeApi = typeof gmp?.buildUrl === 'function';

  return useGetEntities<ReportConfig>({
    gmpMethod: async ({filter}) => {
      const queryFilter = filter instanceof Filter ? filter : ALL_FILTER;

      if (!canUseNativeApi) {
        return gmp.reportconfigs.get({filter: queryFilter});
      }

      const reportConfigs = await fetchAllNativeReportConfigsForDropdown(gmp);
      return nativeDropdownResponse(reportConfigs, queryFilter);
    },
    queryId: 'get_report_configs',
    filter: ALL_FILTER,
    refetchInterval: false,
    keepPreviousData: true,
  });
};

export const useGetReportExportFileName = () => {
  const gmp = useGmp();
  const token = useSessionToken();

  return useQuery<string | undefined>({
    queryKey: ['user_settings', token, 'reportexportfilename'],
    queryFn: async () => {
      const response = await gmp.user.currentSettings();
      const settings = response.data;
      const setting = settings?.reportexportfilename;
      return isDefined(setting) ? String(setting.value) : undefined;
    },
    enabled: Boolean(token),
  });
};
