/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useCallback, useEffect, useMemo, useState} from 'react';
import {
  fetchNativeReportErrors,
  nativeReportErrorsQueryFromFilter,
  type NativeReportErrorItem,
} from 'gmp/native-api/reports';
import type Filter from 'gmp/models/filter';
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

interface NativeErrorsTabProps {
  reportFilter: Filter;
  reportId: string;
}

const sortQuery = (field: string, direction: SortDirectionType) =>
  direction === SortDirection.DESC
    ? `-${field === 'error' ? 'description' : field}`
    : field === 'error'
      ? 'description'
      : field;

const sortFieldFromQuery = (sort: string) => {
  const field = sort.replace(/^-/, '') || 'created_at';
  return field === 'description' ? 'error' : field;
};

const sortDirectionFromQuery = (sort: string): SortDirectionType =>
  sort.startsWith('-') ? SortDirection.DESC : SortDirection.ASC;

const NativeErrorsTab = ({reportFilter, reportId}: NativeErrorsTabProps) => {
  const [_] = useTranslation();
  const gmp = useGmp();
  const initialQuery = useMemo(
    () => nativeReportErrorsQueryFromFilter(reportFilter),
    [reportFilter],
  );
  const [filterText, setFilterText] = useState(initialQuery.filter);
  const [page, setPage] = useState(initialQuery.page);
  const [sortBy, setSortBy] = useState(sortFieldFromQuery(initialQuery.sort));
  const [sortDir, setSortDir] = useState<SortDirectionType>(
    sortDirectionFromQuery(initialQuery.sort),
  );
  const [data, setData] = useState<{
    items: NativeReportErrorItem[];
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

  const loadErrors = useCallback(async () => {
    setLoading(true);
    setError(undefined);
    try {
      const response = await fetchNativeReportErrors(gmp, reportId, query);
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
    void loadErrors();
  }, [loadErrors]);

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

  const errors = data?.items ?? [];

  return (
    <>
      <PageActions>
        <TextField
          grow={1}
          placeholder={_('Filter report error messages')}
          title={_('Filter')}
          value={filterText}
          onChange={handleFilterChange}
        />
        <Button
          disabled={loading}
          title={_('Reload')}
          onClick={() => void loadErrors()}
        />
      </PageActions>
      {renderPageControls()}
      {error && <ErrorMessage>{error}</ErrorMessage>}
      {loading && !data ? (
        <Loading />
      ) : (
        <Table data-testid="native-raw-report-errors-table">
          <TableBody>
            <TableRow>
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="created_at"
                title={_('Created')}
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
                sortBy="nvt_oid"
                title={_('NVT')}
                onSortChange={handleSortChange}
              />
              <TableHead
                currentSortBy={sortBy}
                currentSortDir={sortDir}
                sortBy="error"
                title={_('Description')}
                onSortChange={handleSortChange}
              />
              <TableHead>{_('Raw Evidence')}</TableHead>
            </TableRow>
            {errors.length === 0 && <EmptyRow colSpan={6} />}
            {errors.map(errorItem => (
              <TableRow key={errorItem.id}>
                <TableData>{formatDate(errorItem.createdAt)}</TableData>
                <TableData>{errorItem.host}</TableData>
                <TableData>{errorItem.port}</TableData>
                <TableData>{errorItem.nvtOid}</TableData>
                <TableData>{errorItem.description}</TableData>
                <TableData>
                  <Link to={`/result/${errorItem.id}`}>
                    {errorItem.id}
                  </Link>
                </TableData>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </>
  );
};

export default NativeErrorsTab;
