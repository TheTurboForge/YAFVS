/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useCallback, useEffect, useMemo, useState} from 'react';
import CollectionCounts from 'gmp/collection/collection-counts';
import Filter from 'gmp/models/filter';
import ErrorPanel from 'web/components/error/ErrorPanel';
import Loading from 'web/components/loading/Loading';
import {NO_RELOAD} from 'web/components/loading/Reload';
import useGetResults from 'web/hooks/use-query/results';
import useFilterSortBy from 'web/hooks/useFilterSortBy';
import usePagination from 'web/hooks/usePagination';
import useTranslation from 'web/hooks/useTranslation';
import ResultsTable from 'web/pages/results/ResultsTable';

interface ScopeReportResultsTabProps {
  scopeReportId: string;
}

const DEFAULT_SCOPE_REPORT_RESULTS_FILTER =
  'levels=chml rows=100 min_qod=70 first=1 sort-reverse=severity';

const ScopeReportResultsTab = ({scopeReportId}: ScopeReportResultsTabProps) => {
  const [_] = useTranslation();

  const baseFilter = useMemo(
    () =>
      Filter.fromString(DEFAULT_SCOPE_REPORT_RESULTS_FILTER).set(
        '_and_scope_report_id',
        scopeReportId,
      ),
    [scopeReportId],
  );

  const [resultsFilter, setResultsFilter] = useState<Filter>(baseFilter);

  useEffect(() => {
    setResultsFilter(baseFilter);
  }, [baseFilter]);

  const {data, isLoading, isFetching, isError, error} = useGetResults({
    filter: resultsFilter,
    refetchInterval: NO_RELOAD,
  });

  const updateFilter = useCallback(
    (newFilter: Filter) => {
      setResultsFilter(
        newFilter.copy().set('_and_scope_report_id', scopeReportId),
      );
    },
    [scopeReportId],
  );

  const [sortBy, sortDir, handleSortChange] = useFilterSortBy(
    resultsFilter,
    updateFilter,
  );

  const [
    handleFirstClick,
    handleLastClick,
    handleNextClick,
    handlePreviousClick,
  ] = usePagination(
    resultsFilter,
    data?.entitiesCounts ?? new CollectionCounts(),
    updateFilter,
  );

  if (isError) {
    return (
      <ErrorPanel
        error={error}
        message={_('Error while loading Results for Scope Report {{id}}', {
          id: scopeReportId,
        })}
      />
    );
  }

  if (isLoading && !data) {
    return <Loading />;
  }

  const {entities: results = [], entitiesCounts: resultsCounts} = data || {};
  const displayedFilter = resultsFilter.copy().delete('_and_scope_report_id');

  return (
    <ResultsTable
      delta={false}
      entities={results}
      entitiesCounts={resultsCounts}
      filter={displayedFilter}
      footer={false}
      isUpdating={isFetching && !data}
      links={true}
      sortBy={sortBy || 'severity'}
      sortDir={sortDir}
      toggleDetailsIcon={true}
      onFirstClick={handleFirstClick}
      onLastClick={handleLastClick}
      onNextClick={handleNextClick}
      onPreviousClick={handlePreviousClick}
      onSortChange={handleSortChange}
    />
  );
};

export default ScopeReportResultsTab;
