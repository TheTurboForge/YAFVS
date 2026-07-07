/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import Filter, {VULNS_FILTER_FILTER} from 'gmp/models/filter';
import {VulnerabilityIcon} from 'web/components/icon';
import ManualIcon from 'web/components/icon/ManualIcon';
import Layout from 'web/components/layout/Layout';
import PageTitle from 'web/components/layout/PageTitle';
import EntitiesPage from 'web/entities/EntitiesPage';
import withEntitiesContainer from 'web/entities/withEntitiesContainer';
import useTranslation from 'web/hooks/useTranslation';
import VulnsTable from 'web/pages/vulns/Table';
import VulnerabilityFilterDialog from 'web/pages/vulns/VulnerabilityFilterDialog';
import {
  loadEntities,
  selector as entitiesSelector,
} from 'web/store/entities/vulns';
import PropTypes from 'web/utils/PropTypes';

const ToolBarIcons = () => {
  const [_] = useTranslation();
  return (
    <Layout>
      <ManualIcon
        anchor="displaying-all-existing-vulnerabilities"
        page="reports"
        title={_('Vulnerabilities')}
      />
    </Layout>
  );
};

const Page = ({filter, onFilterChanged, ...props}) => {
  const [_] = useTranslation();
  return (
    <React.Fragment>
      <PageTitle title={_('Vulnerabilities')} />
      <EntitiesPage
        {...props}
        filter={filter}
        filterEditDialog={VulnerabilityFilterDialog}
        filtersFilter={VULNS_FILTER_FILTER}
        sectionIcon={<VulnerabilityIcon size="large" />}
        table={VulnsTable}
        tags={false}
        title={_('Vulnerabilities')}
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

const FALLBACK_VULNS_LIST_FILTER = Filter.fromString(
  'sort-reverse=severity first=1',
);

export default withEntitiesContainer('vulnerability', {
  fallbackFilter: FALLBACK_VULNS_LIST_FILTER,
  entitiesSelector,
  loadEntities,
  nativeListExportExtension: 'json',
})(Page);
