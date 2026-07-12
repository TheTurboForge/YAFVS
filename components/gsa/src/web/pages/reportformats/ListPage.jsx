/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import {REPORT_FORMATS_FILTER_FILTER} from 'gmp/models/filter';
import {ReportFormatIcon} from 'web/components/icon';
import ManualIcon from 'web/components/icon/ManualIcon';
import IconDivider from 'web/components/layout/IconDivider';
import PageTitle from 'web/components/layout/PageTitle';
import EntitiesPage from 'web/entities/EntitiesPage';
import withEntitiesContainer from 'web/entities/withEntitiesContainer';
import useTranslation from 'web/hooks/useTranslation';
import ReportFormatFilterDialog from 'web/pages/reportformats/ReportFormatFilterDialog';
import ReportFormatsTable from 'web/pages/reportformats/Table';
import {
  loadEntities,
  selector as entitiesSelector,
} from 'web/store/entities/reportformats';
import PropTypes from 'web/utils/PropTypes';

const ToolBarIcons = () => {
  const [_] = useTranslation();
  return (
    <IconDivider>
      <ManualIcon
        anchor="managing-report-formats"
        page="reports"
        title={_('Help: Report Formats')}
      />
    </IconDivider>
  );
};

const ReportFormatsPage = ({onChanged, onError, ...props}) => {
  const [_] = useTranslation();
  return (
    <>
      <PageTitle title={_('Report Formats')} />
      <EntitiesPage
        {...props}
        filterEditDialog={ReportFormatFilterDialog}
        filtersFilter={REPORT_FORMATS_FILTER_FILTER}
        sectionIcon={<ReportFormatIcon size="large" />}
        table={ReportFormatsTable}
        title={_('Report Formats')}
        toolBarIcons={ToolBarIcons}
        onChanged={onChanged}
        onError={onError}
      />
    </>
  );
};

ReportFormatsPage.propTypes = {
  showSuccess: PropTypes.func.isRequired,
  onChanged: PropTypes.func.isRequired,
  onError: PropTypes.func.isRequired,
};

export default withEntitiesContainer('reportformat', {
  entitiesSelector,
  loadEntities,
  nativeListExportExtension: 'json',
})(ReportFormatsPage);
