/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useCallback, useEffect, useMemo, useState} from 'react';
import {
  fetchNativeScopeReportApplications,
  fetchNativeScopeReportCves,
  fetchNativeScopeReportErrors,
  fetchNativeScopeReportHosts,
  fetchNativeScopeReportOperatingSystems,
  fetchNativeScopeReportPorts,
  fetchNativeScopeReportResults,
  fetchNativeScopeReportTlsCertificates,
  type NativeCollection,
  type NativeCollectionQuery,
  type ScopeReportApplicationItem,
  type ScopeReportCveItem,
  type ScopeReportErrorMessageItem,
  type ScopeReportHostItem,
  type ScopeReportOperatingSystemItem,
  type ScopeReportPortItem,
  type ScopeReportResultItem,
  type ScopeReportTlsCertificateItem,
} from 'gmp/native-api/scope-report-collections';
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

const PAGE_SIZE = 25;

export type NativeScopeReportEvidenceKind =
  | 'results'
  | 'hosts'
  | 'ports'
  | 'applications'
  | 'operatingSystems'
  | 'cves'
  | 'tlsCertificates'
  | 'errors';

interface NativeScopeReportEvidenceTabProps {
  kind: NativeScopeReportEvidenceKind;
  scopeId: string;
  scopeReportId: string;
}

interface EvidenceState {
  results?: NativeCollection<ScopeReportResultItem>;
  hosts?: NativeCollection<ScopeReportHostItem>;
  ports?: NativeCollection<ScopeReportPortItem>;
  applications?: NativeCollection<ScopeReportApplicationItem>;
  operatingSystems?: NativeCollection<ScopeReportOperatingSystemItem>;
  cves?: NativeCollection<ScopeReportCveItem>;
  tlsCertificates?: NativeCollection<ScopeReportTlsCertificateItem>;
  errors?: NativeCollection<ScopeReportErrorMessageItem>;
}

const defaultSortBy = (kind: NativeScopeReportEvidenceKind) => {
  switch (kind) {
    case 'results':
      return 'severity';
    case 'hosts':
      return 'host';
    case 'ports':
      return 'port';
    case 'applications':
      return 'name';
    case 'operatingSystems':
      return 'name';
    case 'cves':
      return 'max_severity';
    case 'tlsCertificates':
      return 'not_after';
    case 'errors':
      return 'created_at';
    default:
      return 'host';
  }
};

const defaultSortDir = (kind: NativeScopeReportEvidenceKind): SortDirectionType =>
  kind === 'hosts' ||
  kind === 'ports' ||
  kind === 'applications' ||
  kind === 'operatingSystems'
    ? SortDirection.ASC
    : SortDirection.DESC;

const sortQuery = (field: string, direction: SortDirectionType) =>
  direction === SortDirection.DESC ? `-${field}` : field;

const membershipLabel = (value: string) => {
  switch (value) {
    case 'organization':
      return 'Organization';
    case 'member':
      return 'Member';
    case 'candidate':
      return 'Candidate';
    default:
      return value || '-';
  }
};

const authStateLabel = (value: string) => {
  switch (value) {
    case 'authenticated':
      return 'Authenticated';
    case 'authentication_failed':
      return 'Authentication Failed';
    case 'no_credential_path':
      return 'No Credential Path';
    case 'unknown':
      return 'Unknown';
    default:
      return value || 'Unknown';
  }
};

const NativeScopeReportEvidenceTab = ({
  kind,
  scopeId,
  scopeReportId,
}: NativeScopeReportEvidenceTabProps) => {
  const [_] = useTranslation();
  const gmp = useGmp();
  const [filterText, setFilterText] = useState('');
  const [page, setPage] = useState(1);
  const [sortBy, setSortBy] = useState(defaultSortBy(kind));
  const [sortDir, setSortDir] = useState<SortDirectionType>(defaultSortDir(kind));
  const [data, setData] = useState<EvidenceState>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    setPage(1);
    setSortBy(defaultSortBy(kind));
    setSortDir(defaultSortDir(kind));
    setData({});
  }, [kind, scopeReportId]);

  const query: NativeCollectionQuery = useMemo(
    () => ({
      page,
      pageSize: PAGE_SIZE,
      sort: sortQuery(sortBy, sortDir),
      filter: filterText.trim() || undefined,
    }),
    [filterText, page, sortBy, sortDir],
  );

  const loadEvidence = useCallback(async () => {
    setLoading(true);
    setError(undefined);
    try {
      if (kind === 'hosts') {
        setData({
          hosts: await fetchNativeScopeReportHosts(
            gmp,
            scopeId,
            scopeReportId,
            query,
          ),
        });
      } else if (kind === 'ports') {
        setData({
          ports: await fetchNativeScopeReportPorts(
            gmp,
            scopeId,
            scopeReportId,
            query,
          ),
        });
      } else if (kind === 'applications') {
        setData({
          applications: await fetchNativeScopeReportApplications(
            gmp,
            scopeId,
            scopeReportId,
            query,
          ),
        });
      } else if (kind === 'operatingSystems') {
        setData({
          operatingSystems: await fetchNativeScopeReportOperatingSystems(
            gmp,
            scopeId,
            scopeReportId,
            query,
          ),
        });
      } else if (kind === 'results') {
        setData({
          results: await fetchNativeScopeReportResults(
            gmp,
            scopeId,
            scopeReportId,
            query,
          ),
        });
      } else if (kind === 'cves') {
        setData({
          cves: await fetchNativeScopeReportCves(
            gmp,
            scopeId,
            scopeReportId,
            query,
          ),
        });
      } else if (kind === 'tlsCertificates') {
        setData({
          tlsCertificates: await fetchNativeScopeReportTlsCertificates(
            gmp,
            scopeId,
            scopeReportId,
            query,
          ),
        });
      } else {
        setData({
          errors: await fetchNativeScopeReportErrors(
            gmp,
            scopeId,
            scopeReportId,
            query,
          ),
        });
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [gmp, kind, query, scopeId, scopeReportId]);

  useEffect(() => {
    void loadEvidence();
  }, [loadEvidence]);

  const collection = data[kind];
  const total = collection?.page.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
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

  const renderResults = () => {
    const results = data.results?.items ?? [];
    return (
      <Table>
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
              </TableData>
              <TableData>{result.host}</TableData>
              <TableData>{result.port}</TableData>
              <TableData align="end">{result.qod}</TableData>
              <TableData>{formatDate(result.createdAt)}</TableData>
              <TableData>
                <Link to={`/report/${result.sourceReportId}`}>
                  {result.sourceReportId}
                </Link>
              </TableData>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    );
  };

  const renderPorts = () => {
    const ports = data.ports?.items ?? [];
    return (
      <Table>
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
          {ports.length === 0 && <EmptyRow colSpan={7} />}
          {ports.map(port => (
            <TableRow key={port.port}>
              <TableData>{port.port}</TableData>
              <TableData>{port.protocol}</TableData>
              <TableData>
                <SeverityBar severity={port.maxSeverity} />
              </TableData>
              <TableData align="end">{port.hostCount}</TableData>
              <TableData align="end">{port.resultCount}</TableData>
              <TableData align="end">{port.vulnerabilityCount}</TableData>
              <TableData align="end">{port.sourceReportIds.length}</TableData>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    );
  };

  const renderHosts = () => {
    const hosts = data.hosts?.items ?? [];
    return (
      <Table>
        <TableBody>
          <TableRow>
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
              sortBy="scope_membership"
              title={_('Scope Membership')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="authenticated_scan_state"
              title={_('Authentication')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="source_report_count"
              title={_('Source Reports')}
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
          </TableRow>
          {hosts.length === 0 && <EmptyRow colSpan={6} />}
          {hosts.map(host => (
            <TableRow key={host.host}>
              <TableData>{host.host}</TableData>
              <TableData>{membershipLabel(host.scopeMembership)}</TableData>
              <TableData>{authStateLabel(host.authenticatedScanState)}</TableData>
              <TableData align="end">{host.sourceReportCount}</TableData>
              <TableData align="end">{host.resultCount}</TableData>
              <TableData align="end">{host.vulnerabilityCount}</TableData>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    );
  };

  const renderCves = () => {
    const cves = data.cves?.items ?? [];
    return (
      <Table>
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
            <TableHead>{_('Source Reports')}</TableHead>
          </TableRow>
          {cves.length === 0 && <EmptyRow colSpan={5} />}
          {cves.map(cve => (
            <TableRow key={cve.id}>
              <TableData>{cve.id}</TableData>
              <TableData>
                <SeverityBar severity={cve.maxSeverity} />
              </TableData>
              <TableData align="end">{cve.affectedSystemCount}</TableData>
              <TableData align="end">{cve.resultCount}</TableData>
              <TableData align="end">{cve.sourceReportIds.length}</TableData>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    );
  };

  const renderApplications = () => {
    const applications = data.applications?.items ?? [];
    return (
      <Table>
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
            <TableRow key={`${application.name}-${application.cpe}`}>
              <TableData>{application.name}</TableData>
              <TableData>{application.cpe || '-'}</TableData>
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
      <Table>
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
          {operatingSystems.map(os => (
            <TableRow key={`${os.name}-${os.cpe}`}>
              <TableData>{os.name}</TableData>
              <TableData>{os.cpe || '-'}</TableData>
              <TableData>
                <SeverityBar severity={os.maxSeverity} />
              </TableData>
              <TableData align="end">{os.hostCount}</TableData>
              <TableData align="end">{os.resultCount}</TableData>
              <TableData align="end">{os.vulnerabilityCount}</TableData>
              <TableData align="end">{os.sourceReportIds.length}</TableData>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    );
  };

  const renderTlsCertificates = () => {
    const certificates = data.tlsCertificates?.items ?? [];
    return (
      <Table>
        <TableBody>
          <TableRow>
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="fingerprint_sha256"
              title={_('SHA-256 Fingerprint')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="subject"
              title={_('Subject')}
              onSortChange={handleSortChange}
            />
            <TableHead
              currentSortBy={sortBy}
              currentSortDir={sortDir}
              sortBy="issuer"
              title={_('Issuer')}
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
              sortBy="not_after"
              title={_('Not After')}
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
              <TableData>
                {certificate.fingerprintSha256 || certificate.id}
              </TableData>
              <TableData>{certificate.subject || '-'}</TableData>
              <TableData>{certificate.issuer || '-'}</TableData>
              <TableData>{certificate.serial || '-'}</TableData>
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

  const renderErrors = () => {
    const errors = data.errors?.items ?? [];
    return (
      <Table>
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
            <TableHead>{_('Description')}</TableHead>
            <TableHead>{_('Raw Report')}</TableHead>
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
                <Link to={`/report/${errorItem.sourceReportId}`}>
                  {errorItem.sourceReportId}
                </Link>
              </TableData>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    );
  };

  return (
    <>
      <PageActions>
        <TextField
          grow={1}
          placeholder={_('Filter scope-report evidence')}
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
      {loading && !collection ? (
        <Loading />
      ) : kind === 'results' ? (
        renderResults()
      ) : kind === 'hosts' ? (
        renderHosts()
      ) : kind === 'ports' ? (
        renderPorts()
      ) : kind === 'applications' ? (
        renderApplications()
      ) : kind === 'operatingSystems' ? (
        renderOperatingSystems()
      ) : kind === 'cves' ? (
        renderCves()
      ) : kind === 'tlsCertificates' ? (
        renderTlsCertificates()
      ) : (
        renderErrors()
      )}
    </>
  );
};

export default NativeScopeReportEvidenceTab;
