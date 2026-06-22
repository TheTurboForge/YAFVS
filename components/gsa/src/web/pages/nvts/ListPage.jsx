/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import Filter, {NVTS_FILTER_FILTER} from 'gmp/models/filter';
import {NvtIcon} from 'web/components/icon';
import ManualIcon from 'web/components/icon/ManualIcon';
import PageTitle from 'web/components/layout/PageTitle';
import EntitiesPage from 'web/entities/EntitiesPage';
import withEntitiesContainer from 'web/entities/withEntitiesContainer';
import useTranslation from 'web/hooks/useTranslation';
import NvtFilterDialog from 'web/pages/nvts/NvtFilterDialog';
import NvtsTable from 'web/pages/nvts/Table';
import {
  loadEntities,
  selector as entitiesSelector,
} from 'web/store/entities/nvts';
import PropTypes from 'web/utils/PropTypes';
export const ToolBarIcons = () => {
  const [_] = useTranslation();

  return (
    <ManualIcon
      anchor="vulnerability-tests-vt"
      page="managing-secinfo"
      title={_('Help: NVTs')}
    />
  );
};

const Page = ({filter, onFilterChanged, ...props}) => {
  const [_] = useTranslation();

  return (
    <React.Fragment>
      <PageTitle title={_('NVTs')} />
      <EntitiesPage
        {...props}
        createFilterType="info"
        filter={filter}
        filterEditDialog={NvtFilterDialog}
        filtersFilter={NVTS_FILTER_FILTER}
        sectionIcon={<NvtIcon size="large" />}
        table={NvtsTable}
        title={_('NVTs')}
        toolBarIcons={ToolBarIcons}
        onFilterChanged={onFilterChanged}
      />
    </React.Fragment>
  );
};

Page.propTypes = {
  filter: PropTypes.filter,
  onFilterChanged: PropTypes.func.isRequired,
};

const fallbackFilter = Filter.fromString('sort-reverse=created');

export default withEntitiesContainer('nvt', {
  entitiesSelector,
  fallbackFilter,
  loadEntities,
})(Page);
