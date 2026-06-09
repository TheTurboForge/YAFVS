/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useState} from 'react';
import type Filter from 'gmp/models/filter';
import {isActive, type TaskStatus} from 'gmp/models/task';
import ErrorPanel from 'web/components/error/ErrorPanel';
import Loading from 'web/components/loading/Loading';
import {
  NO_RELOAD,
  USE_DEFAULT_RELOAD_INTERVAL_ACTIVE,
} from 'web/components/loading/Reload';
import useGetReportHosts from 'web/hooks/use-query/report-hosts';
import useTranslation from 'web/hooks/useTranslation';
import HostsTab from 'web/pages/reports/details/HostsTab';

export interface HostsTabContentProps {
  reportId: string;
  status: TaskStatus;
  reportFilter: Filter;
}

const HostsTabContent = ({
  reportId,
  status,
  reportFilter,
}: HostsTabContentProps) => {
  const [_] = useTranslation();
  const [{sortField, sortReverse}, setSorting] = useState({
    sortField: 'severity',
    sortReverse: true,
  });

  const {data, isLoading, isFetching, isError, error} = useGetReportHosts({
    reportId,
    filter: reportFilter,
    refetchInterval: isActive(status)
      ? USE_DEFAULT_RELOAD_INTERVAL_ACTIVE
      : NO_RELOAD,
  });

  const handleSortChange = (newSortField: string) => {
    setSorting(prev => ({
      sortField: newSortField,
      sortReverse: newSortField === prev.sortField ? !prev.sortReverse : false,
    }));
  };

  if (isLoading && !data) {
    return <Loading />;
  }

  if (isError) {
    return (
      <ErrorPanel
        error={error}
        message={_('Error while loading Hosts for Report {{reportId}}', {
          reportId,
        })}
      />
    );
  }

  const hosts = {
    counts: data?.entitiesCounts,
    entities: data?.entities ?? [],
  };

  return (
    <HostsTab
      counts={hosts.counts}
      filter={reportFilter}
      hosts={hosts.entities}
      isUpdating={isFetching}
      sortField={sortField}
      sortReverse={sortReverse}
      onSortChange={handleSortChange}
    />
  );
};

export default HostsTabContent;
