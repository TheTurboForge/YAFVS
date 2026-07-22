/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useCallback, useEffect, useMemo, useState} from 'react';
import {
  fetchNativeReportHosts,
  nativeReportHostsQueryFromFilter,
  type NativeReportHostItem,
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

interface NativeHostsTabProps {
  reportFilter: Filter;
  reportId: string;
}

const sortQuery = (field: string, direction: SortDirectionType) =>
  direction === SortDirection.DESC ? `-${field}` : field;

const sortFieldFromQuery = (sort: string) => sort.replace(/^-/, '') || 'host';

const sortDirectionFromQuery = (sort: string): SortDirectionType =>
  sort.startsWith('-') ? SortDirection.DESC : SortDirection.ASC;

const osLabel = (host: NativeReportHostItem) =>
  host.bestOsTxt || host.bestOsCpe || '';

const NativeHostsTab = ({reportFilter, reportId}: NativeHostsTabProps) => {
  const [_] = useTranslation();
  const gmp = useGmp();
  const initialQuery = useMemo(
    () => nativeReportHostsQueryFromFilter(reportFilter),
    [reportFilter],
  );
  const [filterText, setFilterText] = useState(initialQuery.filter);
  const [page, setPage] = useState(initialQuery.page);
  const [sortBy, setSortBy] = useState(sortFieldFromQuery(initialQuery.sort));
  const [sortDir, setSortDir] = useState<SortDirectionType>(
    sortDirectionFromQuery(initialQuery.sort),
  );
  const [data, setData] = useState<{
    items: NativeReportHostItem[];
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

  const loadHosts = useCallback(async () => {
    setLoading(true);
    setError(undefined);
    try {
      const response = await fetchNativeReportHosts(gmp, reportId, query);
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
    void loadHosts();
  }, [loadHosts]);

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

  const hosts = data?.items ?? [];

  return (
    <>
      <PageActions>
        <TextField
          grow={1}
          placeholder={_('Filter report hosts')}
          title={_('Filter')}
          value={filterText}
          onChange={handleFilterChange}
        />
        <Button
          disabled={loading}
          title={_('Reload')}
          onClick={() => void loadHosts()}
        />
      </PageActions>
      {renderPageControls()}
      {error && <ErrorMessage>{error}</ErrorMessage>}
      {loading && !data ? (
        <Loading />
      ) : (
        <Table data-testid="native-raw-report-hosts-table">
          <TableBody>
            <TableRow>
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="host"
                title={_('IP Address')}
                onSortChange={handleSortChange}
              />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="hostname"
                title={_('Hostname')}
                onSortChange={handleSortChange}
              />
              <TableHead title={_('OS')} />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="ports_count"
                title={_('Ports')}
                onSortChange={handleSortChange}
              />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="applications_count"
                title={_('Apps')}
                onSortChange={handleSortChange}
              />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="authentication_state"
                title={_('Auth')}
                onSortChange={handleSortChange}
              />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="start_time"
                title={_('Start')}
                onSortChange={handleSortChange}
              />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="end_time"
                title={_('End')}
                onSortChange={handleSortChange}
              />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="vulnerability_count"
                title={_('Vulnerabilities')}
                onSortChange={handleSortChange}
              />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="result_count"
                title={_('Total')}
                onSortChange={handleSortChange}
              />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="severity"
                title={_('Severity')}
                onSortChange={handleSortChange}
              />
            </TableRow>
            {hosts.length === 0 && <EmptyRow colSpan={11} />}
            {hosts.map(host => (
              <TableRow key={`${host.sourceReportId}:${host.host}`}>
                <TableData>
                  <Link filter={`name=${host.host}`} to="hosts">
                    {host.host}
                  </Link>
                </TableData>
                <TableData>{host.hostname}</TableData>
                <TableData>{osLabel(host)}</TableData>
                <TableData align="end">{host.portsCount}</TableData>
                <TableData align="end">{host.applicationsCount}</TableData>
                <TableData>{host.authenticationState}</TableData>
                <TableData>{formatDate(host.startTime)}</TableData>
                <TableData>{formatDate(host.endTime)}</TableData>
                <TableData align="end">{host.vulnerabilityCount}</TableData>
                <TableData align="end">{host.resultCount}</TableData>
                <TableData>
                  <SeverityBar severity={host.maxSeverity} />
                </TableData>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </>
  );
};

export default NativeHostsTab;
