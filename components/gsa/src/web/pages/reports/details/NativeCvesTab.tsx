/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useCallback, useEffect, useMemo, useState} from 'react';
import {
  fetchNativeReportCves,
  nativeReportCvesQueryFromFilter,
  type NativeReportCveItem,
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
import {EmptyRow, ErrorMessage, PageActions} from 'web/pages/scopes/common';
import SortDirection, {type SortDirectionType} from 'web/utils/sort-direction';

interface NativeCvesTabProps {
  reportFilter: Filter;
  reportId: string;
}

const sortQuery = (field: string, direction: SortDirectionType) =>
  direction === SortDirection.DESC ? `-${field}` : field;

const sortFieldFromQuery = (sort: string) =>
  sort.replace(/^-/, '') || 'max_severity';

const sortDirectionFromQuery = (sort: string): SortDirectionType =>
  sort.startsWith('-') ? SortDirection.DESC : SortDirection.ASC;

const NativeCvesTab = ({reportFilter, reportId}: NativeCvesTabProps) => {
  const [_] = useTranslation();
  const gmp = useGmp();
  const initialQuery = useMemo(
    () => nativeReportCvesQueryFromFilter(reportFilter),
    [reportFilter],
  );
  const [filterText, setFilterText] = useState(initialQuery.filter);
  const [page, setPage] = useState(initialQuery.page);
  const [sortBy, setSortBy] = useState(sortFieldFromQuery(initialQuery.sort));
  const [sortDir, setSortDir] = useState<SortDirectionType>(
    sortDirectionFromQuery(initialQuery.sort),
  );
  const [data, setData] = useState<{
    items: NativeReportCveItem[];
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

  const loadCves = useCallback(async () => {
    setLoading(true);
    setError(undefined);
    try {
      const response = await fetchNativeReportCves(gmp, reportId, query);
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
    void loadCves();
  }, [loadCves]);

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

  const cves = data?.items ?? [];

  return (
    <>
      <PageActions>
        <TextField
          grow={1}
          placeholder={_('Filter report CVEs')}
          title={_('Filter')}
          value={filterText}
          onChange={handleFilterChange}
        />
        <Button
          disabled={loading}
          title={_('Reload')}
          onClick={() => void loadCves()}
        />
      </PageActions>
      {renderPageControls()}
      {error && <ErrorMessage>{error}</ErrorMessage>}
      {loading && !data ? (
        <Loading />
      ) : (
        <Table data-testid="native-raw-report-cves-table">
          <TableBody>
            <TableRow>
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="id"
                title={_('CVE')}
                onSortChange={handleSortChange}
              />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="max_severity"
                title={_('Max Severity')}
                onSortChange={handleSortChange}
              />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="affected_system_count"
                title={_('Affected Systems')}
                onSortChange={handleSortChange}
              />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="result_count"
                title={_('Results')}
                onSortChange={handleSortChange}
              />
            </TableRow>
            {cves.length === 0 && <EmptyRow colSpan={4} />}
            {cves.map(cve => (
              <TableRow key={cve.id}>
                <TableData>
                  <Link to={`/cve/${cve.id}`}>{cve.id}</Link>
                </TableData>
                <TableData>
                  <SeverityBar severity={cve.maxSeverity} />
                </TableData>
                <TableData align="end">{cve.affectedSystemCount}</TableData>
                <TableData align="end">{cve.resultCount}</TableData>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </>
  );
};

export default NativeCvesTab;
