/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useCallback, useEffect, useState} from 'react';
import {useNavigate, useParams} from 'react-router';
import type {ScopeReport} from 'gmp/commands/scopes';
import {TASK_STATUS} from 'gmp/models/task';
import SeverityBar from 'web/components/bar/SeverityBar';
import StatusBar from 'web/components/bar/StatusBar';
import Button from 'web/components/form/Button';
import Column from 'web/components/layout/Column';
import PageTitle from 'web/components/layout/PageTitle';
import Link from 'web/components/link/Link';
import Section from 'web/components/section/Section';
import Tab from 'web/components/tab/Tab';
import TabLayout from 'web/components/tab/TabLayout';
import TabList from 'web/components/tab/TabList';
import TabPanel from 'web/components/tab/TabPanel';
import TabPanels from 'web/components/tab/TabPanels';
import Tabs from 'web/components/tab/Tabs';
import TabsContainer from 'web/components/tab/TabsContainer';
import InfoTable from 'web/components/table/InfoTable';
import Table from 'web/components/table/StripedTable';
import TableBody from 'web/components/table/TableBody';
import TableCol from 'web/components/table/TableCol';
import TableData from 'web/components/table/TableData';
import TableHead from 'web/components/table/TableHead';
import TableRow from 'web/components/table/TableRow';
import useGmp from 'web/hooks/useGmp';
import useTranslation from 'web/hooks/useTranslation';
import MetricsTab from 'web/pages/reports/details/MetricsTab';
import ScopeReportEvidenceTab from 'web/pages/scope-reports/ScopeReportEvidenceTab';
import ScopeReportResultsTab from 'web/pages/scope-reports/ScopeReportResultsTab';
import {
  EmptyRow,
  ErrorMessage,
  formatDate,
  PageActions,
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
      navigate(`/scopes/${report.scopeId}`);
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
        {error ? (
          <ErrorMessage>{error}</ErrorMessage>
        ) : (
          <span>{_('Loading...')}</span>
        )}
      </Column>
    );
  }

  const title = report.name || report.id;

  const informationTab = (
    <InfoTable>
      <colgroup>
        <TableCol width="10%" />
        <TableCol width="90%" />
      </colgroup>
      <TableBody>
        <TableRow>
          <TableData>{_('Scope')}</TableData>
          <TableData>
            <Link to={`/scopes/${report.scopeId}`}>{report.scopeName}</Link>
          </TableData>
        </TableRow>
        <TableRow>
          <TableData>{_('Protection Requirement')}</TableData>
          <TableData>{report.protectionRequirementLabel}</TableData>
        </TableRow>
        <TableRow>
          <TableData>{_('Status')}</TableData>
          <TableData>
            <StatusBar status={TASK_STATUS.done} />
          </TableData>
        </TableRow>
        <TableRow>
          <TableData>{_('Created')}</TableData>
          <TableData>{formatDate(report.created)}</TableData>
        </TableRow>
        <TableRow>
          <TableData>{_('Latest Evidence')}</TableData>
          <TableData>{formatDate(report.latestEvidenceTime)}</TableData>
        </TableRow>
        <TableRow>
          <TableData>{_('Source Reports')}</TableData>
          <TableData>{report.sourceReportCount}</TableData>
        </TableRow>
        <TableRow>
          <TableData>{_('Hosts')}</TableData>
          <TableData>
            {report.hostsWithEvidence}/{report.hostsTotal}
          </TableData>
        </TableRow>
        <TableRow>
          <TableData>{_('Missing Evidence')}</TableData>
          <TableData>{report.hostsMissingEvidence}</TableData>
        </TableRow>
        <TableRow>
          <TableData>{_('Results')}</TableData>
          <TableData>{report.resultsTotal}</TableData>
        </TableRow>
        <TableRow>
          <TableData>{_('Vulnerabilities')}</TableData>
          <TableData>{report.vulnerabilitiesTotal}</TableData>
        </TableRow>
        <TableRow>
          <TableData>{_('Severity')}</TableData>
          <TableData>
            <SeverityBar severity={report.maxSeverity} />
          </TableData>
        </TableRow>
        <TableRow>
          <TableData>{_('Severity Counts')}</TableData>
          <TableData>
            H {report.severityHigh} / M {report.severityMedium} / L{' '}
            {report.severityLow} / Log {report.severityLog} / FP{' '}
            {report.severityFalsePositive}
          </TableData>
        </TableRow>
        <TableRow>
          <TableData>{_('Excluded Candidates')}</TableData>
          <TableData>{report.excludedCandidateHosts}</TableData>
        </TableRow>
      </TableBody>
    </InfoTable>
  );

  const resultsTab = <ScopeReportResultsTab scopeReportId={report.id} />;
  const metricsTab = (
    <MetricsTab id={report.id} scopeId={report.scopeId} source="scopeReport" />
  );
  const hostsTab = <ScopeReportEvidenceTab kind="hosts" report={report} />;
  const portsTab = <ScopeReportEvidenceTab kind="ports" report={report} />;
  const applicationsTab = (
    <ScopeReportEvidenceTab kind="applications" report={report} />
  );
  const operatingSystemsTab = (
    <ScopeReportEvidenceTab kind="operatingSystems" report={report} />
  );
  const cvesTab = <ScopeReportEvidenceTab kind="cves" report={report} />;
  const tlsCertificatesTab = (
    <ScopeReportEvidenceTab kind="tlsCertificates" report={report} />
  );
  const errorsTab = <ScopeReportEvidenceTab kind="errors" report={report} />;

  const sourcesTab = (
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
                <Link to={`/target/${source.targetId}`}>
                  {source.targetName || source.targetId}
                </Link>
              ) : (
                '-'
              )}
            </TableData>
            <TableData>
              {source.taskId ? (
                <Link to={`/task/${source.taskId}`}>
                  {source.taskName || source.taskId}
                </Link>
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
  );

  return (
    <Column>
      <PageTitle title={title} />
      <Section title={_('Scope Report: {{name}}', {name: title})} />
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
        <Link to="/scopes/reports">{_('Scope Reports')}</Link>
        <Link to={`/scopes/${report.scopeId}`}>{_('Scope')}</Link>
      </PageActions>
      {error && <ErrorMessage>{error}</ErrorMessage>}
      <TabsContainer flex="column" grow="1">
        <Tabs>
          <TabLayout align={['start', 'end']} grow="1">
            <TabList align={['start', 'stretch']}>
              <Tab>{_('Information')}</Tab>
              <Tab>{_('Results')}</Tab>
              <Tab>{_('Hosts')}</Tab>
              <Tab>{_('Ports')}</Tab>
              <Tab>{_('Applications')}</Tab>
              <Tab>{_('Operating Systems')}</Tab>
              <Tab>{_('CVEs')}</Tab>
              <Tab>{_('TLS Certificates')}</Tab>
              <Tab>{_('Error Messages')}</Tab>
              <Tab>{_('Metrics')}</Tab>
              <Tab>{_('Evidence Sources')}</Tab>
            </TabList>
          </TabLayout>
          <TabPanels>
            <TabPanel>{informationTab}</TabPanel>
            <TabPanel>{resultsTab}</TabPanel>
            <TabPanel>{hostsTab}</TabPanel>
            <TabPanel>{portsTab}</TabPanel>
            <TabPanel>{applicationsTab}</TabPanel>
            <TabPanel>{operatingSystemsTab}</TabPanel>
            <TabPanel>{cvesTab}</TabPanel>
            <TabPanel>{tlsCertificatesTab}</TabPanel>
            <TabPanel>{errorsTab}</TabPanel>
            <TabPanel>{metricsTab}</TabPanel>
            <TabPanel>{sourcesTab}</TabPanel>
          </TabPanels>
        </Tabs>
      </TabsContainer>
    </Column>
  );
};

export default ScopeReportDetailsPage;
