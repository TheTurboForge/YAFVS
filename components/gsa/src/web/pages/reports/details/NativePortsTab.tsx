/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useCallback, useEffect, useMemo, useState} from 'react';
import {
  fetchNativeReportPorts,
  nativeReportPortsQueryFromFilter,
  type NativeReportPortItem,
} from 'gmp/native-api/reports';
import type Filter from 'gmp/models/filter';
import SeverityBar from 'web/components/bar/SeverityBar';
import Button from 'web/components/form/Button';
import TextField from 'web/components/form/TextField';
import Loading from 'web/components/loading/Loading';
import Table from 'web/components/table/StripedTable';
import TableBody from 'web/components/table/TableBody';
import TableData from 'web/components/table/TableData';
import TableHead from 'web/components/table/TableHead';
import TableRow from 'web/components/table/TableRow';
import useGmp from 'web/hooks/useGmp';
import useTranslation from 'web/hooks/useTranslation';
import {EmptyRow, ErrorMessage, PageActions} from 'web/pages/scopes/common';
import SortDirection, {type SortDirectionType} from 'web/utils/sort-direction';

interface NativePortsTabProps {
  reportFilter: Filter;
  reportId: string;
}

const sortQuery = (field: string, direction: SortDirectionType) =>
  direction === SortDirection.DESC ? `-${field}` : field;

const sortFieldFromQuery = (sort: string) => sort.replace(/^-/, '') || 'port';

const sortDirectionFromQuery = (sort: string): SortDirectionType =>
  sort.startsWith('-') ? SortDirection.DESC : SortDirection.ASC;

const NativePortsTab = ({reportFilter, reportId}: NativePortsTabProps) => {
  const [_] = useTranslation();
  const gmp = useGmp();
  const initialQuery = useMemo(
    () => nativeReportPortsQueryFromFilter(reportFilter),
    [reportFilter],
  );
  const [filterText, setFilterText] = useState(initialQuery.filter);
  const [page, setPage] = useState(initialQuery.page);
  const [sortBy, setSortBy] = useState(sortFieldFromQuery(initialQuery.sort));
  const [sortDir, setSortDir] = useState<SortDirectionType>(
    sortDirectionFromQuery(initialQuery.sort),
  );
  const [data, setData] = useState<{
    items: NativeReportPortItem[];
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

  const loadPorts = useCallback(async () => {
    setLoading(true);
    setError(undefined);
    try {
      const response = await fetchNativeReportPorts(gmp, reportId, query);
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
    void loadPorts();
  }, [loadPorts]);

  const total = data?.total ?? 0;
  const pageSize = data?.pageSize ?? initialQuery.pageSize;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const currentPage = Math.min(page, pageCount);

  useEffect(() => {
    if (page > pageCount) {
      setPage(pageCount);
    }
  }, [page, pageCount]);

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

  const ports = data?.items ?? [];

  return (
    <>
      <PageActions>
        <TextField
          grow={1}
          placeholder={_('Filter report ports')}
          title={_('Filter')}
          value={filterText}
          onChange={handleFilterChange}
        />
        <Button
          disabled={loading}
          title={_('Reload')}
          onClick={() => void loadPorts()}
        />
      </PageActions>
      {renderPageControls()}
      {error && <ErrorMessage>{error}</ErrorMessage>}
      {loading && !data ? (
        <Loading />
      ) : (
        <Table data-testid="native-raw-report-ports-table">
          <TableBody>
            <TableRow>
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
                sortBy="protocol"
                title={_('Protocol')}
                onSortChange={handleSortChange}
              />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="host_count"
                title={_('Hosts')}
                onSortChange={handleSortChange}
              />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="result_count"
                title={_('Results')}
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
                sortBy="max_severity"
                title={_('Severity')}
                onSortChange={handleSortChange}
              />
            </TableRow>
            {ports.length === 0 && <EmptyRow colSpan={6} />}
            {ports.map(port => (
              <TableRow key={port.port}>
                <TableData>{port.port}</TableData>
                <TableData>{port.protocol}</TableData>
                <TableData align="end">{port.hostCount}</TableData>
                <TableData align="end">{port.resultCount}</TableData>
                <TableData align="end">{port.vulnerabilityCount}</TableData>
                <TableData>
                  <SeverityBar severity={port.maxSeverity} />
                </TableData>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </>
  );
};

export default NativePortsTab;
