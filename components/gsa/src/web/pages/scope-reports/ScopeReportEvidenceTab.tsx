/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import Filter from 'gmp/models/filter';
import type ReportTLSCertificate from 'gmp/models/report/tls-certificate';
import {TASK_STATUS} from 'gmp/models/task';
import Column from 'web/components/layout/Column';
import Link from 'web/components/link/Link';
import Section from 'web/components/section/Section';
import type {ScopeReport, ScopeReportSource} from 'gmp/commands/scopes';
import useTranslation from 'web/hooks/useTranslation';
import ApplicationsTab from 'web/pages/reports/details/ApplicationsTab';
import CvesTab from 'web/pages/reports/details/CvesTab';
import ErrorsTab from 'web/pages/reports/details/ErrorsTab';
import HostsTabContent from 'web/pages/reports/details/HostsTabContent';
import OperatingSystemsTab from 'web/pages/reports/details/OperatingSystemsTab';
import PortsTab from 'web/pages/reports/details/PortsTab';
import TLSCertificatesTab from 'web/pages/reports/details/TlsCertificatesTab';
import {formatDate, PageActions} from 'web/pages/scopes/common';

export type ScopeReportEvidenceKind =
  | 'hosts'
  | 'ports'
  | 'applications'
  | 'operatingSystems'
  | 'cves'
  | 'tlsCertificates'
  | 'errors';

interface SourceEvidenceProps {
  kind: ScopeReportEvidenceKind;
  source: ScopeReportSource;
}

interface ScopeReportEvidenceTabProps {
  kind: ScopeReportEvidenceKind;
  report: ScopeReport;
}

const reportFilter = Filter.fromString('rows=25 first=1 sort-reverse=severity');

const renderEvidence = (
  kind: ScopeReportEvidenceKind,
  reportId: string,
) => {
  const ignoreTlsDownload = (_entity: ReportTLSCertificate) => undefined;

  switch (kind) {
    case 'hosts':
      return (
        <HostsTabContent
          reportFilter={reportFilter}
          reportId={reportId}
          status={TASK_STATUS.done}
        />
      );
    case 'ports':
      return <PortsTab reportFilter={reportFilter} reportId={reportId} />;
    case 'applications':
      return (
        <ApplicationsTab
          filter={reportFilter}
          reportId={reportId}
          status={TASK_STATUS.done}
        />
      );
    case 'operatingSystems':
      return (
        <OperatingSystemsTab
          filter={reportFilter}
          reportId={reportId}
          status={TASK_STATUS.done}
        />
      );
    case 'cves':
      return (
        <CvesTab
          filter={reportFilter}
          reportId={reportId}
          status={TASK_STATUS.done}
        />
      );
    case 'tlsCertificates':
      return (
        <TLSCertificatesTab
          reportFilter={reportFilter}
          reportId={reportId}
          status={TASK_STATUS.done}
          onTlsCertificateDownloadClick={ignoreTlsDownload}
        />
      );
    case 'errors':
      return (
        <ErrorsTab
          filter={reportFilter}
          reportId={reportId}
          status={TASK_STATUS.done}
        />
      );
    default:
      return null;
  }
};

const SourceEvidence = ({kind, source}: SourceEvidenceProps) => {
  const [_] = useTranslation();
  const reportId = source.sourceReportId;

  if (!reportId) {
    return null;
  }

  const title = source.targetName || source.taskName || source.sourceReportName || reportId;

  return (
    <Section title={_('Evidence Source: {{name}}', {name: title})}>
      <PageActions>
        {source.targetId && (
          <Link to={`/target/${source.targetId}`}>
            {source.targetName || _('Target')}
          </Link>
        )}
        {source.taskId && (
          <Link to={`/task/${source.taskId}`}>{source.taskName || _('Task')}</Link>
        )}
        <Link to={`/report/${reportId}`}>
          {source.sourceReportName || _('Raw Report')}
        </Link>
        <span>{formatDate(source.scanEnd)}</span>
      </PageActions>
      {renderEvidence(kind, reportId)}
    </Section>
  );
};

const ScopeReportEvidenceTab = ({kind, report}: ScopeReportEvidenceTabProps) => {
  const [_] = useTranslation();
  const selectedSources = report.sources.filter(
    source => source.selected && Boolean(source.sourceReportId),
  );

  if (selectedSources.length === 0) {
    return <span>{_('No source reports are available for this scope report.')}</span>;
  }

  return (
    <Column>
      {selectedSources.map(source => (
        <SourceEvidence
          key={source.id ?? source.sourceReportId}
          kind={kind}
          source={source}
        />
      ))}
    </Column>
  );
};

export default ScopeReportEvidenceTab;
