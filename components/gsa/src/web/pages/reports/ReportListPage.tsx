/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import Filter, {REPORTS_FILTER_FILTER} from 'gmp/models/filter';
import type Report from 'gmp/models/report';
import {isActive} from 'gmp/models/task';
import {isDefined} from 'gmp/utils/identity';
import {ReportIcon} from 'web/components/icon';
import ManualIcon from 'web/components/icon/ManualIcon';
import IconDivider from 'web/components/layout/IconDivider';
import PageTitle from 'web/components/layout/PageTitle';
import {
  USE_DEFAULT_RELOAD_INTERVAL,
  USE_DEFAULT_RELOAD_INTERVAL_ACTIVE,
} from 'web/components/loading/Reload';
import EntitiesPage from 'web/entities/EntitiesPage';
import withEntitiesContainer, {
  type WithEntitiesContainerComponentProps,
} from 'web/entities/withEntitiesContainer';
import useTranslation from 'web/hooks/useTranslation';
import ReportFilterDialog from 'web/pages/reports/ReportFilterDialog';
import ReportsTable from 'web/pages/reports/ReportTable';
import {
  loadEntities,
  selector as entitiesSelector,
} from 'web/store/entities/reports';

type ReportListPageProps = WithEntitiesContainerComponentProps<Report>;

const ToolBarIcons = () => {
  const [_] = useTranslation();
  return (
    <IconDivider>
      <ManualIcon
        anchor="using-and-managing-reports"
        page="reports"
        title={_('Help: Reports')}
      />
    </IconDivider>
  );
};

const ReportListPage = ({
  entities,
  filter,
  onDelete,
  onError,
  onFilterChanged,
  ...props
}: ReportListPageProps) => {
  const [_] = useTranslation();

  const handleReportDeleteClick = (report: Report) => {
    if (!isDefined(onDelete)) {
      return Promise.resolve();
    }
    return onDelete(report);
  };

  return (
    <>
      <PageTitle title={_('Reports')} />
      <EntitiesPage<Report>
        {...props}
        entities={entities}
        filter={filter}
        filterEditDialog={ReportFilterDialog}
        filtersFilter={REPORTS_FILTER_FILTER}
        sectionIcon={<ReportIcon size="large" />}
        table={
          <ReportsTable
            {...props}
            entities={entities}
            filter={filter}
            onReportDeleteClick={handleReportDeleteClick}
          />
        }
        title={_('Reports')}
        toolBarIcons={<ToolBarIcons />}
        onError={onError}
        onFilterChanged={onFilterChanged}
      />
    </>
  );
};

const reportsReloadInterval = ({entities = []}: {entities: Report[]}) =>
  entities.some(entity => isActive(entity.report?.scan_run_status))
    ? USE_DEFAULT_RELOAD_INTERVAL_ACTIVE
    : USE_DEFAULT_RELOAD_INTERVAL;

const FALLBACK_REPORT_LIST_FILTER = Filter.fromString(
  'sort-reverse=date first=1',
);

export default withEntitiesContainer<Report>('report', {
  fallbackFilter: FALLBACK_REPORT_LIST_FILTER,
  entitiesSelector,
  loadEntities,
  reloadInterval: reportsReloadInterval,
})(ReportListPage);
