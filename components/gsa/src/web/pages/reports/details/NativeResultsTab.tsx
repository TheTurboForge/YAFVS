/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useCallback, useEffect, useMemo, useState} from 'react';
import {
  fetchNativeReportResults,
  nativeReportResultsQueryFromFilter,
  type NativeReportResultItem,
} from 'gmp/native-api/reports';
import type Filter from 'gmp/models/filter';
import SeverityBar from 'web/components/bar/SeverityBar';
import Button from 'web/components/form/Button';
import TextField from 'web/components/form/TextField';
import Loading from 'web/components/loading/Loading';
import Link from 'web/components/link/Link';
import Table from 'web/components/table/StripedTable';
import TableBody from 'web/components/table/TableBody';
import TableData from 'web/components/table/TableData';
import TableHead from 'web/components/table/TableHead';
import TableRow from 'web/components/table/TableRow';
import useGmp from 'web/hooks/useGmp';
import useTranslation from 'web/hooks/useTranslation';
import {
  EmptyRow,
  ErrorMessage,
  formatDate,
  PageActions,
} from 'web/pages/scopes/common';
import SortDirection, {type SortDirectionType} from 'web/utils/sort-direction';

interface NativeResultsTabProps {
  reportFilter: Filter;
  reportId: string;
}

const sortQuery = (field: string, direction: SortDirectionType) =>
  direction === SortDirection.DESC ? `-${field}` : field;

const sortFieldFromQuery = (sort: string) => sort.replace(/^-/, '') || 'severity';

const sortDirectionFromQuery = (sort: string): SortDirectionType =>
  sort.startsWith('-') ? SortDirection.DESC : SortDirection.ASC;

const hostLabel = (result: NativeReportResultItem) => {
  if (result.hostname && result.hostname !== result.host) {
    return `${result.host} (${result.hostname})`;
  }
  return result.host;
};

const NativeResultsTab = ({reportFilter, reportId}: NativeResultsTabProps) => {
  const [_] = useTranslation();
  const gmp = useGmp();
  const initialQuery = useMemo(
    () => nativeReportResultsQueryFromFilter(reportFilter),
    [reportFilter],
  );
  const [filterText, setFilterText] = useState(initialQuery.filter);
  const [page, setPage] = useState(initialQuery.page);
  const [sortBy, setSortBy] = useState(sortFieldFromQuery(initialQuery.sort));
  const [sortDir, setSortDir] = useState<SortDirectionType>(
    sortDirectionFromQuery(initialQuery.sort),
  );
  const [data, setData] = useState<{
    items: NativeReportResultItem[];
    total: number;
    pageSize: number;
  }>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    setFilterText(initialQuery.filter);
    setPage(initialQuery.page);
    setSortBy(sortFieldFromQuery(initialQuery.sort));
    setSortDir(sortDirectionFromQuery(initialQuery.sort));
    setData(undefined);
  }, [initialQuery.filter, initialQuery.page, initialQuery.sort, reportId]);

  const query = useMemo(
    () => ({
      page,
      pageSize: initialQuery.pageSize,
      sort: sortQuery(sortBy, sortDir),
      filter: filterText.trim(),
    }),
    [filterText, initialQuery.pageSize, page, sortBy, sortDir],
  );

  const loadResults = useCallback(async () => {
    setLoading(true);
    setError(undefined);
    try {
      const response = await fetchNativeReportResults(gmp, reportId, query);
      setData({
        items: response.items,
        total: response.page.total,
        pageSize: response.page.page_size,
      });
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [gmp, query, reportId]);

  useEffect(() => {
    void loadResults();
  }, [loadResults]);

  const total = data?.total ?? 0;
  const pageSize = data?.pageSize ?? initialQuery.pageSize;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const currentPage = Math.min(page, pageCount);
  const hasData = data !== undefined;

  useEffect(() => {
    if (hasData && page > pageCount) {
      setPage(pageCount);
    }
  }, [hasData, page, pageCount]);

  const handleFilterChange = useCallback((value: string) => {
    setFilterText(value);
    setPage(1);
  }, []);

  const handleSortChange = useCallback(
    (newSortBy: string) => {
      if (newSortBy === sortBy) {
        setSortDir(
          sortDir === SortDirection.ASC ? SortDirection.DESC : SortDirection.ASC,
        );
      } else {
        setSortBy(newSortBy);
        setSortDir(SortDirection.ASC);
      }
      setPage(1);
    },
    [sortBy, sortDir],
  );

  const renderPageControls = () => (
    <PageActions>
      <Button
        disabled={currentPage <= 1 || loading}
        title={_('Previous')}
        onClick={() => setPage(currentPage - 1)}
      />
      <span>
        {_('Page {{page}} of {{pages}}', {
          page: currentPage,
          pages: pageCount,
        })}{' '}
        ({total})
      </span>
      <Button
        disabled={currentPage >= pageCount || loading}
        title={_('Next')}
        onClick={() => setPage(currentPage + 1)}
      />
    </PageActions>
  );

  const results = data?.items ?? [];

  return (
    <>
      <PageActions>
        <TextField
          grow={1}
          placeholder={_('Filter report results')}
          title={_('Filter')}
          value={filterText}
          onChange={handleFilterChange}
        />
        <Button
          disabled={loading}
          title={_('Reload')}
          onClick={() => void loadResults()}
        />
      </PageActions>
      {renderPageControls()}
      {error && <ErrorMessage>{error}</ErrorMessage>}
      {loading && !data ? (
        <Loading />
      ) : (
        <Table data-testid="native-raw-report-results-table">
          <TableBody>
            <TableRow>
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="severity"
                title={_('Severity')}
                onSortChange={handleSortChange}
              />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="name"
                title={_('Name')}
                onSortChange={handleSortChange}
              />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="host"
                title={_('Host')}
                onSortChange={handleSortChange}
              />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="port"
                title={_('Port')}
                onSortChange={handleSortChange}
              />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="qod"
                title={_('QoD')}
                onSortChange={handleSortChange}
              />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="created_at"
                title={_('Created')}
                onSortChange={handleSortChange}
              />
              <TableHead>{_('Raw Evidence')}</TableHead>
            </TableRow>
            {results.length === 0 && <EmptyRow colSpan={7} />}
            {results.map(result => (
              <TableRow key={result.id}>
                <TableData>
                  <SeverityBar severity={result.severity} />
                </TableData>
                <TableData>
                  <Link to={result.rawEvidenceHref}>{result.name || result.id}</Link>
                  {result.nvtFamily && <div>{result.nvtFamily}</div>}
                </TableData>
                <TableData>{hostLabel(result)}</TableData>
                <TableData>{result.port}</TableData>
                <TableData align="end">{result.qod}</TableData>
                <TableData>{formatDate(result.createdAt)}</TableData>
                <TableData>
                  <Link to={result.rawEvidenceHref}>{_('Open')}</Link>
                </TableData>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </>
  );
};

export default NativeResultsTab;
