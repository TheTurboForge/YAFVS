/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useCallback, useEffect, useMemo, useState} from 'react';
import {
  fetchNativeReportApplications,
  fetchNativeReportOperatingSystems,
  fetchNativeReportTlsCertificates,
  nativeReportApplicationsQueryFromFilter,
  nativeReportOperatingSystemsQueryFromFilter,
  nativeReportTlsCertificatesQueryFromFilter,
  type NativeReportApplicationItem,
  type NativeReportOperatingSystemItem,
  type NativeReportTlsCertificateItem,
  type NativeReportQuery,
} from 'gmp/native-api/reports';
import Filter from 'gmp/models/filter';
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
import {
  EmptyRow,
  ErrorMessage,
  formatDate,
  PageActions,
} from 'web/pages/scopes/common';
import SortDirection, {type SortDirectionType} from 'web/utils/sort-direction';

type NativeInventoryEvidenceKind =
  | 'applications'
  | 'operatingSystems'
  | 'tlsCertificates';

interface NativeInventoryEvidenceTabProps {
  kind: NativeInventoryEvidenceKind;
  reportFilter?: Filter;
  reportId: string;
}

interface EvidenceState {
  applications?: {
    items: NativeReportApplicationItem[];
    total: number;
    pageSize: number;
  };
  operatingSystems?: {
    items: NativeReportOperatingSystemItem[];
    total: number;
    pageSize: number;
  };
  tlsCertificates?: {
    items: NativeReportTlsCertificateItem[];
    total: number;
    pageSize: number;
  };
}

const sortQuery = (field: string, direction: SortDirectionType) =>
  direction === SortDirection.DESC ? `-${field}` : field;

const sortFieldFromQuery = (sort: string) => sort.replace(/^-/, '') || 'name';

const sortDirectionFromQuery = (sort: string): SortDirectionType =>
  sort.startsWith('-') ? SortDirection.DESC : SortDirection.ASC;

const initialQueryForKind = (
  kind: NativeInventoryEvidenceKind,
  filter: Filter,
): NativeReportQuery => {
  if (kind === 'operatingSystems') {
    return nativeReportOperatingSystemsQueryFromFilter(filter);
  }
  if (kind === 'tlsCertificates') {
    return nativeReportTlsCertificatesQueryFromFilter(filter);
  }
  return nativeReportApplicationsQueryFromFilter(filter);
};

const filterPlaceholder = (
  kind: NativeInventoryEvidenceKind,
  translate: (text: string) => string,
) => {
  if (kind === 'operatingSystems') {
    return translate('Filter report operating systems');
  }
  if (kind === 'tlsCertificates') {
    return translate('Filter report TLS certificates');
  }
  return translate('Filter report applications');
};

const NativeInventoryEvidenceTab = ({
  kind,
  reportFilter,
  reportId,
}: NativeInventoryEvidenceTabProps) => {
  const [_] = useTranslation();
  const gmp = useGmp();
  const filter = useMemo(() => reportFilter ?? new Filter(), [reportFilter]);
  const initialQuery = useMemo(
    () => initialQueryForKind(kind, filter),
    [filter, kind],
  );
  const [filterText, setFilterText] = useState(initialQuery.filter);
  const [page, setPage] = useState(initialQuery.page);
  const [sortBy, setSortBy] = useState(sortFieldFromQuery(initialQuery.sort));
  const [sortDir, setSortDir] = useState<SortDirectionType>(
    sortDirectionFromQuery(initialQuery.sort),
  );
  const [data, setData] = useState<EvidenceState>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    setFilterText(initialQuery.filter);
    setPage(initialQuery.page);
    setSortBy(sortFieldFromQuery(initialQuery.sort));
    setSortDir(sortDirectionFromQuery(initialQuery.sort));
    setData({});
  }, [initialQuery.filter, initialQuery.page, initialQuery.sort, kind, reportId]);

  const query = useMemo(
    () => ({
      page,
      pageSize: initialQuery.pageSize,
      sort: sortQuery(sortBy, sortDir),
      filter: filterText.trim(),
    }),
    [filterText, initialQuery.pageSize, page, sortBy, sortDir],
  );

  const loadEvidence = useCallback(async () => {
    setLoading(true);
    setError(undefined);
    try {
      if (kind === 'operatingSystems') {
        const response = await fetchNativeReportOperatingSystems(
          gmp,
          reportId,
          query,
        );
        setData({
          operatingSystems: {
            items: response.items,
            total: response.page.total,
            pageSize: response.page.page_size,
          },
        });
      } else if (kind === 'tlsCertificates') {
        const response = await fetchNativeReportTlsCertificates(
          gmp,
          reportId,
          query,
        );
        setData({
          tlsCertificates: {
            items: response.items,
            total: response.page.total,
            pageSize: response.page.page_size,
          },
        });
      } else {
        const response = await fetchNativeReportApplications(gmp, reportId, query);
        setData({
          applications: {
            items: response.items,
            total: response.page.total,
            pageSize: response.page.page_size,
          },
        });
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [gmp, kind, query, reportId]);

  useEffect(() => {
    void loadEvidence();
  }, [loadEvidence]);

  const collection = data[kind];
  const total = collection?.total ?? 0;
  const pageSize = collection?.pageSize ?? initialQuery.pageSize;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const currentPage = Math.min(page, pageCount);
  const hasData = collection !== undefined;

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

  const renderApplications = () => {
    const applications = data.applications?.items ?? [];
    return (
      <Table data-testid="native-raw-report-applications-table">
        <TableBody>
          <TableRow>
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="name"
              title={_('Application')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="cpe"
              title={_('CPE')}
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
            <TableHead>{_('Source Reports')}</TableHead>
          </TableRow>
          {applications.length === 0 && <EmptyRow colSpan={7} />}
          {applications.map(application => (
            <TableRow key={`${application.name}:${application.cpe}`}>
              <TableData>{application.name}</TableData>
              <TableData>{application.cpe}</TableData>
              <TableData>
                <SeverityBar severity={application.maxSeverity} />
              </TableData>
              <TableData align="end">{application.hostCount}</TableData>
              <TableData align="end">{application.resultCount}</TableData>
              <TableData align="end">{application.vulnerabilityCount}</TableData>
              <TableData align="end">
                {application.sourceReportIds.length}
              </TableData>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    );
  };

  const renderOperatingSystems = () => {
    const operatingSystems = data.operatingSystems?.items ?? [];
    return (
      <Table data-testid="native-raw-report-operating-systems-table">
        <TableBody>
          <TableRow>
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="name"
              title={_('Operating System')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="cpe"
              title={_('CPE')}
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
            <TableHead>{_('Source Reports')}</TableHead>
          </TableRow>
          {operatingSystems.length === 0 && <EmptyRow colSpan={7} />}
          {operatingSystems.map(operatingSystem => (
            <TableRow key={`${operatingSystem.name}:${operatingSystem.cpe}`}>
              <TableData>{operatingSystem.name}</TableData>
              <TableData>{operatingSystem.cpe}</TableData>
              <TableData>
                <SeverityBar severity={operatingSystem.maxSeverity} />
              </TableData>
              <TableData align="end">{operatingSystem.hostCount}</TableData>
              <TableData align="end">{operatingSystem.resultCount}</TableData>
              <TableData align="end">
                {operatingSystem.vulnerabilityCount}
              </TableData>
              <TableData align="end">
                {operatingSystem.sourceReportIds.length}
              </TableData>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    );
  };

  const renderTlsCertificates = () => {
    const certificates = data.tlsCertificates?.items ?? [];
    return (
      <Table data-testid="native-raw-report-tls-certificates-table">
        <TableBody>
          <TableRow>
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="subject"
              title={_('Subject DN')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="issuer"
              title={_('Issuer DN')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="serial"
              title={_('Serial')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="not_before"
              title={_('Activates')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="not_after"
              title={_('Expires')}
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
              sortBy="port_count"
              title={_('Ports')}
              onSortChange={handleSortChange}
            />
            <TableHead>{_('Source Reports')}</TableHead>
          </TableRow>
          {certificates.length === 0 && <EmptyRow colSpan={8} />}
          {certificates.map(certificate => (
            <TableRow key={certificate.id}>
              <TableData>{certificate.subject}</TableData>
              <TableData>{certificate.issuer}</TableData>
              <TableData>{certificate.serial}</TableData>
              <TableData>{formatDate(certificate.notBefore)}</TableData>
              <TableData>{formatDate(certificate.notAfter)}</TableData>
              <TableData align="end">{certificate.hostCount}</TableData>
              <TableData align="end">{certificate.portCount}</TableData>
              <TableData align="end">
                {certificate.sourceReportIds.length}
              </TableData>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    );
  };

  const renderTable = () => {
    if (kind === 'operatingSystems') {
      return renderOperatingSystems();
    }
    if (kind === 'tlsCertificates') {
      return renderTlsCertificates();
    }
    return renderApplications();
  };

  return (
    <>
      <PageActions>
        <TextField
          grow={1}
          placeholder={filterPlaceholder(kind, _)}
          title={_('Filter')}
          value={filterText}
          onChange={handleFilterChange}
        />
        <Button
          disabled={loading}
          title={_('Reload')}
          onClick={() => void loadEvidence()}
        />
      </PageActions>
      {renderPageControls()}
      {error && <ErrorMessage>{error}</ErrorMessage>}
      {loading && collection === undefined ? <Loading /> : renderTable()}
    </>
  );
};

export default NativeInventoryEvidenceTab;
