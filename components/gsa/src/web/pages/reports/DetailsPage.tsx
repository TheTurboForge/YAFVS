/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useCallback, useState} from 'react';
import {useQueryClient} from '@tanstack/react-query';
import {useParams} from 'react-router';
import logger from 'gmp/log';
import Filter, {RESET_FILTER} from 'gmp/models/filter';
import type Report from 'gmp/models/report';
import type ReportTLSCertificate from 'gmp/models/report/tls-certificate';
import {isActive} from 'gmp/models/task';
import {fetchNativeReportPdf} from 'gmp/native-api/reports';
import {fetchNativeTarget} from 'gmp/native-api/targets';
import {isDefined} from 'gmp/utils/identity';
import Download from 'web/components/form/Download';
import useDownload from 'web/components/form/useDownload';
import PageTitle from 'web/components/layout/PageTitle';
import DialogNotification from 'web/components/notification/DialogNotification';
import useDialogNotification from 'web/components/notification/useDialogNotification';
import useGetReportCves from 'web/hooks/use-query/report-cves';
import useGetReportTlsCertificates from 'web/hooks/use-query/report-tls-certificates';
import {
  useGetReport,
  useGetReportExportFileName,
  useGetResultsFilters,
} from 'web/hooks/use-query/reports';
import useGmp from 'web/hooks/useGmp';
import usePageFilter from 'web/hooks/usePageFilter';
import useTranslation from 'web/hooks/useTranslation';
import useUserName from 'web/hooks/useUserName';
import Page from 'web/pages/reports/DetailsContent';
import ReportDetailsFilterDialog from 'web/pages/reports/ReportDetailsFilterDialog';
import TargetComponent from 'web/pages/targets/TargetComponent';
import {create_pem_certificate} from 'web/utils/Cert';
import {generateFilename} from 'web/utils/Render';

interface SortState {
  sortField: string;
  sortReverse: boolean;
}

interface SortingState {
  results: SortState;
  apps: SortState;
  ports: SortState;
  hosts: SortState;
  os: SortState;
  cves: SortState;
  tlscerts: SortState;
  errors: SortState;
}

interface ReportTargetRef {
  id: string;
}

const log = logger.getLogger('web.pages.reports.DetailsPage');

const canUseNativeApi = (gmp: {buildUrl?: unknown}) =>
  typeof gmp?.buildUrl === 'function';

const DEFAULT_FILTER = Filter.fromString(
  'levels=chml rows=100 min_qod=70 first=1 sort-reverse=severity result_hosts_only=0',
);

export const REPORT_RESET_FILTER = RESET_FILTER.copy()
  .setSortOrder('sort-reverse')
  .setSortBy('severity');

const hasTargetId = (value: unknown): value is ReportTargetRef => {
  return (
    typeof value === 'object' &&
    value !== null &&
    'id' in value &&
    typeof (value as {id?: unknown}).id === 'string'
  );
};

const getTarget = (entity?: Report) => {
  const report = entity?.report;
  const task = report?.task as {target?: unknown} | undefined;
  const target = task?.target;
  return hasTargetId(target) ? target : undefined;
};

const getReportFilter = (entity?: Report) => {
  return entity?.report?.filter;
};

const initialSorting: SortingState = {
  results: {sortField: 'severity', sortReverse: true},
  apps: {sortField: 'severity', sortReverse: true},
  ports: {sortField: 'severity', sortReverse: true},
  hosts: {sortField: 'severity', sortReverse: true},
  os: {sortField: 'severity', sortReverse: true},
  cves: {sortField: 'severity', sortReverse: true},
  tlscerts: {sortField: 'dn', sortReverse: false},
  errors: {sortField: 'error', sortReverse: false},
};

const ReportDetailsPage = () => {
  const [_] = useTranslation();
  const {id: reportId = ''} = useParams<{id: string}>();
  const gmp = useGmp();
  const queryClient = useQueryClient();
  const username = useUserName();

  const {
    dialogState,
    closeDialog,
    showError,
    showErrorMessage,
    showSuccessMessage,
  } = useDialogNotification();
  const [downloadRef, handleDownload] = useDownload();

  const [showFilterDialog, setShowFilterDialog] = useState(false);
  const [sorting, setSorting] = useState<SortingState>(initialSorting);

  // Filter management
  const [pageFilter, , {changeFilter}] = usePageFilter(
    `report-${reportId}`,
    'result',
    {fallbackFilter: DEFAULT_FILTER},
  );

  // Report entity
  const getRefetchInterval = useCallback(
    (entity?: Report) => {
      if (!isDefined(entity) || !isDefined(entity.report)) {
        return false as const;
      }
      return isActive(entity.report.scan_run_status)
        ? gmp.settings.reloadIntervalActive
        : false;
    },
    [gmp.settings.reloadIntervalActive],
  );

  const {
    data: entity,
    error: queryError,
    isError,
    isLoading,
    isFetching,
  } = useGetReport({
    id: reportId,
    filter: pageFilter,
    refetchInterval: getRefetchInterval,
  });

  const reportError = isError ? queryError : undefined;

  const reportFilter = getReportFilter(entity);
  const {data: reportTlsCertificatesData} = useGetReportTlsCertificates({
    reportId,
    filter: reportFilter,
  });

  const {data: reportCvesData} = useGetReportCves({
    reportId,
    filter: reportFilter,
  });

  // Filters list for Powerfilter dropdown
  const {data: filtersData, isLoading: isLoadingFilters} =
    useGetResultsFilters();
  const filters = filtersData?.entities ?? [];

  // User settings: report export filename
  const {data: reportExportFileName} = useGetReportExportFileName();

  // Derive counts from report entity
  const report = entity?.report;

  const resultsCounts = report?.results?.counts;
  const hostsCounts = report?.hosts?.counts;
  const portsCounts = report?.ports?.counts;
  const applicationsCounts = report?.applications?.counts;
  const operatingSystemsCounts = report?.operatingsystems?.counts;
  const cvesCounts = reportCvesData?.entitiesCounts;
  const tlsCertificatesCounts =
    reportTlsCertificatesData?.entitiesCounts ??
    report?.tlsCertificates?.counts;
  const errorsCounts = report?.errors?.counts;

  // Handlers
  const handleFilterChange = useCallback(
    (filter: Filter) => {
      changeFilter(filter);
    },
    [changeFilter],
  );

  const handleFilterRemoveClick = useCallback(() => {
    handleFilterChange(REPORT_RESET_FILTER);
  }, [handleFilterChange]);

  const handleFilterResetClick = useCallback(() => {
    handleFilterChange(DEFAULT_FILTER);
  }, [handleFilterChange]);

  const handleAddToAssets = useCallback(async () => {
    if (!entity?.id) return;
    try {
      await gmp.report.addAssets({
        id: entity.id,
        filter: reportFilter?.toFilterString(),
      });
      showSuccessMessage(
        _(
          'Report content added to Assets with QoD>=70% and Overrides enabled.',
        ),
      );
      await queryClient.invalidateQueries({queryKey: ['get_report']});
    } catch (error) {
      log.error(error);
      showError(error as Error);
    }
  }, [
    entity,
    gmp,
    reportFilter,
    showSuccessMessage,
    showError,
    queryClient,
    _,
  ]);

  const handleRemoveFromAssets = useCallback(async () => {
    if (!entity?.id) return;
    try {
      await gmp.report.removeAssets({
        id: entity.id,
        filter: reportFilter?.toFilterString(),
      });
      showSuccessMessage(_('Report content removed from Assets.'));
      await queryClient.invalidateQueries({queryKey: ['get_report']});
    } catch (error) {
      log.error(error);
      showError(error as Error);
    }
  }, [
    entity,
    gmp,
    reportFilter,
    showSuccessMessage,
    showError,
    queryClient,
    _,
  ]);

  const handleFilterEditClick = useCallback(() => {
    setShowFilterDialog(true);
  }, []);

  const handleFilterDialogClose = useCallback(() => {
    setShowFilterDialog(false);
  }, []);

  const handleReportDownload = useCallback(async () => {
    if (!entity) return;
    try {
      const data = await fetchNativeReportPdf(gmp, entity.id as string);
      const filename = generateFilename({
        creationTime: entity.creationTime,
        extension: 'pdf',
        fileNameFormat: reportExportFileName,
        id: entity.id as string,
        modificationTime: entity.modificationTime,
        reportFormat: 'PDF',
        resourceName: entity.task?.name,
        resourceType: 'report',
        username,
      });

      handleDownload({filename, data, mimetype: 'application/pdf'});
    } catch (error) {
      log.error(error);
      showError(error as Error);
    }
  }, [entity, gmp, handleDownload, reportExportFileName, showError, username]);

  const handleTlsCertificateDownload = useCallback(
    (cert: ReportTLSCertificate) => {
      if (!cert.data || !cert.serial) return;
      handleDownload({
        filename: 'tls-cert-' + cert.serial + '.pem',
        mimetype: 'application/x-x509-ca-cert',
        data: create_pem_certificate(cert.data),
      });
    },
    [handleDownload],
  );

  const handleFilterCreated = useCallback(
    (filter: Filter) => {
      handleFilterChange(filter);
      void queryClient.invalidateQueries({queryKey: ['get_filters']});
    },
    [handleFilterChange, queryClient],
  );

  const handleFilterAddLogLevel = useCallback(() => {
    if (!reportFilter) return;
    let levels = reportFilter.get('levels', '') as string;

    if (!levels.includes('g')) {
      levels += 'g';
      const levelFilter = reportFilter.copy();
      levelFilter.set('levels', levels);
      handleFilterChange(levelFilter);
    }
  }, [reportFilter, handleFilterChange]);

  const handleFilterRemoveSeverity = useCallback(() => {
    if (!reportFilter) return;

    if (reportFilter.has('severity')) {
      const levelFilter = reportFilter.copy();
      levelFilter.delete('severity');
      handleFilterChange(levelFilter);
    }
  }, [reportFilter, handleFilterChange]);

  const handleFilterDecreaseMinQoD = useCallback(() => {
    if (!reportFilter) return;

    if (reportFilter.has('min_qod')) {
      const levelFilter = reportFilter.copy();
      levelFilter.set('min_qod', 30);
      handleFilterChange(levelFilter);
    }
  }, [reportFilter, handleFilterChange]);

  const handleSortChange = useCallback(
    (name: string, sortField: string) => {
      const prev = sorting[name as keyof SortingState];
      const sortReverse =
        sortField === prev.sortField ? !prev.sortReverse : false;

      setSorting(prevSorting => ({
        ...prevSorting,
        [name]: {sortField, sortReverse},
      }));
    },
    [sorting],
  );

  const handleChanged = useCallback(() => {
    void queryClient.invalidateQueries({queryKey: ['get_report']});
  }, [queryClient]);

  const handleError = useCallback(
    (error: Error) => {
      log.error(error);
      showError(error);
    },
    [showError],
  );

  const loadTarget = useCallback(async () => {
    if (!entity) return;
    const target = getTarget(entity);
    if (!isDefined(target?.id)) return;

    if (canUseNativeApi(gmp)) {
      const response = await fetchNativeTarget(gmp, target.id);
      return {data: response.target};
    }

    return gmp.target.get({id: target.id});
  }, [entity, gmp]);

  return (
    <>
      <DialogNotification {...dialogState} onCloseClick={closeDialog} />
      <Download ref={downloadRef} />
      <PageTitle title={_('Report Details')} />
      <TargetComponent onSaveError={handleError}>
        {({edit}) => (
          <Page
            applicationsCounts={applicationsCounts}
            cvesCounts={cvesCounts}
            entity={entity}
            errorsCounts={errorsCounts}
            filters={filters}
            hostsCounts={hostsCounts}
            isLoading={isLoading}
            isLoadingFilters={isLoadingFilters}
            isUpdating={isFetching && !isLoading}
            operatingSystemsCounts={operatingSystemsCounts}
            pageFilter={pageFilter}
            portsCounts={portsCounts}
            reportError={reportError}
            reportFilter={reportFilter}
            reportId={reportId}
            resetFilter={REPORT_RESET_FILTER}
            resultsCounts={resultsCounts}
            showError={showError as (...args: unknown[]) => void}
            showErrorMessage={showErrorMessage}
            showSuccessMessage={showSuccessMessage}
            sorting={sorting}
            task={isDefined(report) ? report.task : undefined}
            tlsCertificatesCounts={tlsCertificatesCounts}
            onAddToAssetsClick={handleAddToAssets}
            onError={handleError}
            onFilterAddLogLevelClick={handleFilterAddLogLevel}
            onFilterChanged={handleFilterChange}
            onFilterDecreaseMinQoDClick={handleFilterDecreaseMinQoD}
            onFilterEditClick={handleFilterEditClick}
            onFilterRemoveClick={handleFilterRemoveClick}
            onFilterRemoveSeverityClick={handleFilterRemoveSeverity}
            onFilterResetClick={handleFilterResetClick}
            onRemoveFromAssetsClick={handleRemoveFromAssets}
            onReportDownloadClick={handleReportDownload}
            onSortChange={handleSortChange}
            onTagSuccess={handleChanged}
            onTargetEditClick={async () => {
              const response = await loadTarget();
              if (response) void edit(response.data);
            }}
            onTlsCertificateDownloadClick={handleTlsCertificateDownload}
          />
        )}
      </TargetComponent>
      {showFilterDialog && reportFilter && (
        <ReportDetailsFilterDialog
          filter={reportFilter}
          onClose={handleFilterDialogClose}
          onFilterChanged={handleFilterChange}
          onFilterCreated={handleFilterCreated}
        />
      )}
    </>
  );
};

export default ReportDetailsPage;
