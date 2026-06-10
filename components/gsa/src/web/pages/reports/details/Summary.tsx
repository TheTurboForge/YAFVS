/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 * SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React, {useState, useEffect} from 'react';
import styled from 'styled-components';
import {
  type Date as GmpDate,
  duration as createDuration,
} from 'gmp/models/date';
import type Filter from 'gmp/models/filter';
import type ReportReport from 'gmp/models/report/report';
import {TASK_STATUS} from 'gmp/models/task';
import {isDefined} from 'gmp/utils/identity';
import StatusBar from 'web/components/bar/StatusBar';
import DateTime from 'web/components/date/DateTime';
import ErrorPanel from 'web/components/error/ErrorPanel';
import Layout from 'web/components/layout/Layout';
import DetailsLink from 'web/components/link/DetailsLink';
import Table from 'web/components/table/InfoTable';
import TableBody from 'web/components/table/TableBody';
import TableCol from 'web/components/table/TableCol';
import TableData from 'web/components/table/TableData';
import TableRow from 'web/components/table/TableRow';
import useTranslation from 'web/hooks/useTranslation';

interface UpdatingTableProps {
  $isUpdating: boolean;
}

interface SummaryProps {
  filter: Filter;
  isUpdating?: boolean;
  links?: boolean;
  report: ReportReport;
  reportId: string;
  reportError?: Error;
}

const UpdatingTable = styled(Table)<UpdatingTableProps>`
  opacity: ${props => (props.$isUpdating ? '0.2' : '1.0')};
`;

const Summary = ({
  filter,
  isUpdating = false,
  links = true,
  report,
  reportId,
  reportError,
}: SummaryProps) => {
  const [_] = useTranslation();
  const {
    cves,
    hosts,
    result_count,
    results,
    scan_end,
    scan_run_status,
    scan_start,
    // @ts-expect-error
    slave,
    task,
    timezone,
    timezone_abbrev,
    vulns,
  } = report;

  const {id, name, comment, progress} = task ?? {};

  const [hostsCount, setHostsCount] = useState(0);

  const scanDuration = (start: GmpDate, end: GmpDate) => {
    const dur = createDuration(end.diff(start));
    const hours = dur.hours();
    const days = dur.days();
    const mins = dur.minutes();

    if (hours === 0 && days === 0 && mins === 0 && dur.asSeconds() > 0) {
      return dur.humanize();
    }

    let minutes: string | number = mins;
    if (minutes < 10) {
      minutes = '0' + minutes;
    }

    if (days === 0) {
      return _('{{hours}}:{{minutes}} h', {hours, minutes});
    }

    if (days === 1) {
      return _('{{days}} day {{hours}}:{{minutes}} h', {
        days,
        hours,
        minutes,
      });
    }

    return _('{{days}} days {{hours}}:{{minutes}} h', {
      days,
      hours,
      minutes,
    });
  };

  useEffect(() => {
    if (isDefined(hosts?.counts?.all)) {
      setHostsCount(hosts.counts.all);
    }
  }, [hosts]);

  const filterString = isDefined(filter)
    ? filter.simple().toFilterString()
    : '';

  const status = scan_run_status;

  const isEnded = isDefined(scan_end) && scan_end.isValid();
  const resultCount = result_count?.full ?? results?.counts?.all;
  const vulnerabilityCount = vulns?.all;
  const cveCount = cves?.counts?.all;

  return (
    <Layout flex="column">
      {isDefined(reportError) && (
        <ErrorPanel
          error={reportError}
          message={_('Error while loading Report {{reportId}}', {reportId})}
        />
      )}
      <UpdatingTable $isUpdating={isUpdating}>
        <colgroup>
          <TableCol width="10%" />
          <TableCol width="90%" />
        </colgroup>
        <TableBody>
          <TableRow>
            <TableData>{_('Task Name')}</TableData>
            <TableData>
              <span>
                <DetailsLink
                  id={id as string}
                  textOnly={!links}
                  type="task"
                >
                  {name}
                </DetailsLink>
              </span>
            </TableData>
          </TableRow>
          {isDefined(comment) && (
            <TableRow>
              <TableData>{_('Comment')}</TableData>
              <TableData>{comment}</TableData>
            </TableRow>
          )}
          {isDefined(scan_start) && (
            <TableRow>
              <TableData>{_('Scan Time')}</TableData>
              <TableData flex="row">
                <DateTime date={scan_start} />
                {isEnded && (
                  <React.Fragment>
                    {' - '}
                    <DateTime date={scan_end} />
                  </React.Fragment>
                )}
              </TableData>
            </TableRow>
          )}
          {isEnded && (
            <TableRow>
              <TableData>{_('Scan Duration')}</TableData>
              <TableData>
                {scanDuration(scan_start as GmpDate, scan_end as GmpDate)}
              </TableData>
            </TableRow>
          )}
          <TableRow>
            <TableData>{_('Scan Status')}</TableData>
            <TableData>
              <StatusBar progress={progress} status={status} />
            </TableData>
          </TableRow>
          {isDefined(slave) && (
            <TableRow>
              <TableData>{_('Scan sensor')}</TableData>
              <TableData>{slave.name}</TableData>
            </TableRow>
          )}
          {hostsCount > 0 && (
            <TableRow>
              <TableData>{_('Hosts scanned')}</TableData>
              <TableData>{hostsCount}</TableData>
            </TableRow>
          )}
          {isDefined(resultCount) && (
            <TableRow>
              <TableData>{_('Results')}</TableData>
              <TableData>{resultCount}</TableData>
            </TableRow>
          )}
          {isDefined(vulnerabilityCount) && (
            <TableRow>
              <TableData>{_('Vulnerabilities')}</TableData>
              <TableData>{vulnerabilityCount}</TableData>
            </TableRow>
          )}
          {isDefined(cveCount) && (
            <TableRow>
              <TableData>{_('CVEs')}</TableData>
              <TableData>{cveCount}</TableData>
            </TableRow>
          )}
          <TableRow>
            <TableData>{_('Filter')}</TableData>
            <TableData>{filterString}</TableData>
          </TableRow>
          <TableRow>
            <TableData>{_('Timezone')}</TableData>
            <TableData>
              {timezone} ({timezone_abbrev})
            </TableData>
          </TableRow>
        </TableBody>
      </UpdatingTable>
    </Layout>
  );
};

export default Summary;
