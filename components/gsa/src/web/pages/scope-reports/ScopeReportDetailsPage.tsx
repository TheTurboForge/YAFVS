/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useCallback, useEffect, useState} from 'react';
import {useNavigate, useParams} from 'react-router';
import type {ScopeReport} from 'gmp/commands/scopes';
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

const ScopeReportDetailsPage = () => {
  const [_] = useTranslation();
  const gmp = useGmp();
  const navigate = useNavigate();
  const {id = ''} = useParams();
  const [report, setReport] = useState<ScopeReport>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();

  const loadReport = useCallback(async () => {
    if (!id) {
      return;
    }
    setLoading(true);
    setError(undefined);
    try {
      const response = await gmp.scopereports.getOne(id);
      setReport(response.data);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [gmp, id]);

  useEffect(() => {
    void loadReport();
  }, [loadReport]);

  const deleteReport = useCallback(async () => {
    if (!report) {
      return;
    }
    setLoading(true);
    setError(undefined);
    try {
      await gmp.scopereports.delete({id: report.id});
      navigate('/reports');
    } catch (err) {
      setError(String(err));
      setLoading(false);
    }
  }, [gmp, navigate, report]);

  if (!report) {
    return (
      <Column>
        <PageTitle title={_('Scope Report')} />
        <Section title={_('Scope Report')} />
        {error ? <ErrorMessage>{error}</ErrorMessage> : <span>{_('Loading...')}</span>}
      </Column>
    );
  }

  return (
    <Column>
      <PageTitle title={report.name} />
      <Section title={report.name} />
      <SummaryGrid>
        <SummaryItem label={_('Scope')} value={<Link to={`/scope/${report.scopeId}`}>{report.scopeName}</Link>} />
        <SummaryItem label={_('Protection Requirement')} value={report.protectionRequirementLabel} />
        <SummaryItem label={_('Latest Evidence')} value={formatDate(report.latestEvidenceTime)} />
        <SummaryItem label={_('Source Reports')} value={report.sourceReportCount} />
        <SummaryItem label={_('Hosts With Evidence')} value={`${report.hostsWithEvidence}/${report.hostsTotal}`} />
        <SummaryItem label={_('Missing Evidence')} value={report.hostsMissingEvidence} />
        <SummaryItem label={_('Results')} value={report.resultsTotal} />
        <SummaryItem label={_('Vulnerabilities')} value={report.vulnerabilitiesTotal} />
      </SummaryGrid>
      <SummaryGrid>
        <SummaryItem label={_('High')} value={report.severityHigh} />
        <SummaryItem label={_('Medium')} value={report.severityMedium} />
        <SummaryItem label={_('Low')} value={report.severityLow} />
        <SummaryItem label={_('Log')} value={report.severityLog} />
        <SummaryItem label={_('False Positive')} value={report.severityFalsePositive} />
        <SummaryItem label={_('Excluded Candidates')} value={report.excludedCandidateHosts} />
      </SummaryGrid>
      <PageActions>
        <Button
          disabled={loading}
          title={_('Reload')}
          onClick={() => void loadReport()}
        />
        <Button
          disabled={loading}
          title={_('Delete')}
          onClick={() => void deleteReport()}
        />
        <Link to="/reports">{_('Scope Reports')}</Link>
      </PageActions>
      {error && <ErrorMessage>{error}</ErrorMessage>}

      <Section title={_('Evidence Sources')} />
      <Table>
        <TableBody>
          <TableRow>
            <TableHead>{_('Target')}</TableHead>
            <TableHead>{_('Task')}</TableHead>
            <TableHead>{_('Raw Report')}</TableHead>
            <TableHead>{_('Scan End')}</TableHead>
            <TableHead>{_('Selected')}</TableHead>
            <TableHead>{_('Reason')}</TableHead>
          </TableRow>
          {report.sources.length === 0 && <EmptyRow colSpan={6} />}
          {report.sources.map(source => (
            <TableRow key={source.id ?? `${source.targetId}-${source.sourceReportId}`}>
              <TableData>
                {source.targetId ? (
                  <Link to={`/target/${source.targetId}`}>{source.targetName || source.targetId}</Link>
                ) : (
                  '-'
                )}
              </TableData>
              <TableData>
                {source.taskId ? (
                  <Link to={`/task/${source.taskId}`}>{source.taskName || source.taskId}</Link>
                ) : (
                  '-'
                )}
              </TableData>
              <TableData>
                {source.sourceReportId ? (
                  <Link to={`/report/${source.sourceReportId}`}>
                    {source.sourceReportName || source.sourceReportId}
                  </Link>
                ) : (
                  '-'
                )}
              </TableData>
              <TableData>{formatDate(source.scanEnd)}</TableData>
              <TableData>{source.selected ? _('Yes') : _('No')}</TableData>
              <TableData>{source.reason ?? '-'}</TableData>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <Section title={_('Top Results')} />
      <Table>
        <TableBody>
          <TableRow>
            <TableHead>{_('Host')}</TableHead>
            <TableHead>{_('Port')}</TableHead>
            <TableHead>{_('NVT')}</TableHead>
            <TableHead>{_('Severity')}</TableHead>
            <TableHead>{_('Created')}</TableHead>
            <TableHead>{_('Evidence')}</TableHead>
          </TableRow>
          {report.topResults.length === 0 && <EmptyRow colSpan={6} />}
          {report.topResults.map(result => (
            <TableRow key={`${result.sourceReportId}-${result.id}`}>
              <TableData>{result.host || '-'}</TableData>
              <TableData>{result.port || '-'}</TableData>
              <TableData>{result.nvtName || result.nvtOid || '-'}</TableData>
              <TableData>{result.severityLabel || result.severity}</TableData>
              <TableData>{formatDate(result.created)}</TableData>
              <TableData>
                {result.sourceReportId ? (
                  <Link to={`/report/${result.sourceReportId}`}>{_('Raw Report')}</Link>
                ) : (
                  '-'
                )}
              </TableData>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Column>
  );
};

export default ScopeReportDetailsPage;
