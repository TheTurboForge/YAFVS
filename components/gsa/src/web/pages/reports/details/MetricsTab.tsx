/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useCallback, useEffect, useState} from 'react';
import type {ReportMetrics} from 'gmp/commands/report-metrics';
import {
  fetchNativeReportMetrics,
  fetchNativeScopeReportMetrics,
} from 'gmp/native-api/report-metrics';
import ErrorPanel from 'web/components/error/ErrorPanel';
import Loading from 'web/components/loading/Loading';
import Section from 'web/components/section/Section';
import InfoTable from 'web/components/table/InfoTable';
import Table from 'web/components/table/StripedTable';
import TableBody from 'web/components/table/TableBody';
import TableCol from 'web/components/table/TableCol';
import TableData from 'web/components/table/TableData';
import TableHead from 'web/components/table/TableHead';
import TableRow from 'web/components/table/TableRow';
import useGmp from 'web/hooks/useGmp';
import useTranslation from 'web/hooks/useTranslation';

interface MetricsTabProps {
  id: string;
  scopeId?: string;
  source: 'report' | 'scopeReport';
}

const formatNumber = (value: number, digits = 2) => value.toFixed(digits);

const authStateLabel = (state: string, translate: (value: string) => string) => {
  switch (state) {
    case 'authenticated':
      return translate('Authenticated');
    case 'authentication_failed':
      return translate('Authentication Failed');
    case 'no_credential_path':
      return translate('No Credential Path');
    default:
      return translate('Unknown');
  }
};

const MetricsTab = ({id, scopeId, source}: MetricsTabProps) => {
  const [_] = useTranslation();
  const gmp = useGmp();
  const [metrics, setMetrics] = useState<ReportMetrics>();
  const [error, setError] = useState<Error>();
  const [isLoading, setIsLoading] = useState(false);

  const loadMetrics = useCallback(async () => {
    if (!id) {
      return;
    }

    setIsLoading(true);
    setError(undefined);
    try {
      const response =
        source === 'scopeReport'
          ? await fetchNativeScopeReportMetrics(gmp, scopeId ?? '', id)
          : await fetchNativeReportMetrics(gmp, id);
      setMetrics(response);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setIsLoading(false);
    }
  }, [gmp, id, scopeId, source]);

  useEffect(() => {
    void loadMetrics();
  }, [loadMetrics]);

  if (error) {
    return <ErrorPanel error={error} message={_('Error while loading metrics')} />;
  }

  if (isLoading && !metrics) {
    return <Loading />;
  }

  if (!metrics) {
    return null;
  }

  const {summary} = metrics;

  return (
    <>
      <Section title={_('Summary')}>
        <InfoTable>
          <colgroup>
            <TableCol width="20%" />
            <TableCol width="80%" />
          </colgroup>
          <TableBody>
            <TableRow>
              <TableData>{_('Average System CVSS Load')}</TableData>
              <TableData>{formatNumber(summary.averageSystemCvssLoad)}</TableData>
            </TableRow>
            <TableRow>
              <TableData>{_('Total CVSS Load')}</TableData>
              <TableData>{formatNumber(summary.totalSystemCvssLoad)}</TableData>
            </TableRow>
            <TableRow>
              <TableData>{_('Authenticated Scan Coverage')}</TableData>
              <TableData>
                {formatNumber(summary.authenticatedScanCoveragePercent, 1)}%
              </TableData>
            </TableRow>
            <TableRow>
              <TableData>{_('Alive Systems')}</TableData>
              <TableData>{summary.aliveSystemCount}</TableData>
            </TableRow>
            <TableRow>
              <TableData>{_('Vulnerabilities')}</TableData>
              <TableData>{summary.vulnerabilityCount}</TableData>
            </TableRow>
          </TableBody>
        </InfoTable>
      </Section>

      <Section title={_('Systems')}>
        <Table>
          <TableBody>
            <TableRow>
              <TableHead>{_('System')}</TableHead>
              <TableHead>{_('CVSS Load')}</TableHead>
              <TableHead>{_('Max CVSS')}</TableHead>
              <TableHead>{_('Vulnerabilities')}</TableHead>
              <TableHead>{_('Authentication')}</TableHead>
              <TableHead>{_('Source Reports')}</TableHead>
            </TableRow>
            {metrics.systems.map(system => (
              <TableRow key={system.host}>
                <TableData>{system.host}</TableData>
                <TableData>{formatNumber(system.cvssLoad)}</TableData>
                <TableData>{formatNumber(system.maxCvss)}</TableData>
                <TableData>{system.vulnerabilityCount}</TableData>
                <TableData>{authStateLabel(system.authenticationState, _)}</TableData>
                <TableData>{system.sourceReportCount}</TableData>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Section>

      <Section title={_('Vulnerabilities')}>
        <Table>
          <TableBody>
            <TableRow>
              <TableHead>{_('NVT')}</TableHead>
              <TableHead>{_('CVSS')}</TableHead>
              <TableHead>{_('Affected Systems')}</TableHead>
              <TableHead>{_('CVSS Load')}</TableHead>
              <TableHead>{_('Average Contribution')}</TableHead>
              <TableHead>{_('Source Reports')}</TableHead>
            </TableRow>
            {metrics.vulnerabilities.map(vulnerability => (
              <TableRow key={vulnerability.nvtOid}>
                <TableData>
                  {vulnerability.name || vulnerability.nvtOid}
                </TableData>
                <TableData>{formatNumber(vulnerability.cvssScore)}</TableData>
                <TableData>{vulnerability.affectedSystemCount}</TableData>
                <TableData>{formatNumber(vulnerability.cvssLoad)}</TableData>
                <TableData>
                  {formatNumber(vulnerability.averageContribution)}
                </TableData>
                <TableData>{vulnerability.sourceReportCount}</TableData>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Section>
    </>
  );
};

export default MetricsTab;
