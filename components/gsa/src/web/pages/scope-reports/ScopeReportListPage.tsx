/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useCallback, useEffect, useMemo, useState} from 'react';
import type {Scope, ScopeReport} from 'gmp/commands/scopes';
import Button from 'web/components/form/Button';
import Column from 'web/components/layout/Column';
import PageTitle from 'web/components/layout/PageTitle';
import Link from 'web/components/link/Link';
import Section from 'web/components/section/Section';
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
  SummaryGrid,
  SummaryItem,
} from 'web/pages/scopes/common';

const ScopeReportListPage = () => {
  const [_] = useTranslation();
  const gmp = useGmp();
  const [reports, setReports] = useState<ScopeReport[]>([]);
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();

  const organizationScope = useMemo(
    () => scopes.find(scope => scope.global || scope.name === 'Organization'),
    [scopes],
  );

  const loadReports = useCallback(async () => {
    setLoading(true);
    setError(undefined);
    try {
      const [scopeResponse, reportResponse] = await Promise.all([
        gmp.scopes.get({details: 0}),
        gmp.scopereports.get({details: 1}),
      ]);
      setScopes(scopeResponse.data);
      setReports(reportResponse.data);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [gmp]);

  useEffect(() => {
    void loadReports();
  }, [loadReports]);

  const generateOrganizationReport = useCallback(async () => {
    if (!organizationScope) {
      return;
    }
    setLoading(true);
    setError(undefined);
    try {
      await gmp.scopes.generateReport({id: organizationScope.id});
      await loadReports();
    } catch (err) {
      setError(String(err));
      setLoading(false);
    }
  }, [gmp, loadReports, organizationScope]);

  const latestReport = reports[0];

  return (
    <Column>
      <PageTitle title={_('Scope Reports')} />
      <Section title={_('Scope Reports')} />
      <SummaryGrid>
        <SummaryItem label={_('Scope Reports')} value={reports.length} />
        <SummaryItem
          label={_('Latest Evidence')}
          value={formatDate(latestReport?.latestEvidenceTime)}
        />
        <SummaryItem
          label={_('Source Reports')}
          value={latestReport?.sourceReportCount ?? 0}
        />
        <SummaryItem
          label={_('Vulnerabilities')}
          value={latestReport?.vulnerabilitiesTotal ?? 0}
        />
      </SummaryGrid>
      <PageActions>
        <Button
          disabled={loading || !organizationScope}
          title={_('Generate Organization Report')}
          onClick={() => void generateOrganizationReport()}
        />
        <Button
          disabled={loading}
          title={_('Reload')}
          onClick={() => void loadReports()}
        />
        <Link to="/scopes">{_('Scopes')}</Link>
      </PageActions>
      {error && <ErrorMessage>{error}</ErrorMessage>}
      <Table>
        <TableBody>
          <TableRow>
            <TableHead>{_('Name')}</TableHead>
            <TableHead>{_('Scope')}</TableHead>
            <TableHead>{_('Created')}</TableHead>
            <TableHead>{_('Latest Evidence')}</TableHead>
            <TableHead>{_('Source Reports')}</TableHead>
            <TableHead>{_('Hosts')}</TableHead>
            <TableHead>{_('Vulnerabilities')}</TableHead>
            <TableHead>{_('Severity')}</TableHead>
          </TableRow>
          {reports.length === 0 && <EmptyRow colSpan={8} />}
          {reports.map(report => (
            <TableRow key={report.id}>
              <TableData>
                <Link to={`/scope-report/${report.id}`}>{report.name}</Link>
              </TableData>
              <TableData>
                <Link to={`/scope/${report.scopeId}`}>{report.scopeName}</Link>
              </TableData>
              <TableData>{formatDate(report.created)}</TableData>
              <TableData>{formatDate(report.latestEvidenceTime)}</TableData>
              <TableData>{report.sourceReportCount}</TableData>
              <TableData>
                {report.hostsWithEvidence}/{report.hostsTotal}
              </TableData>
              <TableData>{report.vulnerabilitiesTotal}</TableData>
              <TableData>
                H {report.severityHigh} / M {report.severityMedium} / L{' '}
                {report.severityLow}
              </TableData>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Column>
  );
};

export default ScopeReportListPage;
