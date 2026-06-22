/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 * SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import {rendererWith, screen} from 'web/testing';
import CollectionCounts from 'gmp/collection/collection-counts';
import type Filter from 'gmp/models/filter';
import type ReportReport from 'gmp/models/report/report';
import {TASK_STATUS} from 'gmp/models/task';
import {createSession} from 'gmp/testing';
import Summary from 'web/pages/reports/details/Summary';

const createFilter = (value: string): Filter =>
  ({
    simple: () => ({
      toFilterString: () => value,
    }),
  }) as unknown as Filter;

const createBaseReport = (): ReportReport =>
  ({
    id: 'report-1',
    scan_run_status: TASK_STATUS.running,
    cves: {
      counts: new CollectionCounts({all: 3}),
    },
    hosts: {
      counts: {all: 4},
    },
    result_count: {
      full: 23,
    },
    task: {
      id: 'task-1',
      name: 'Example Task',
      comment: 'Example comment',
      progress: 42,
      isImport: () => false,
    },
    timezone: 'UTC',
    timezone_abbrev: 'UTC',
    vulns: new CollectionCounts({all: 6}),
  }) as unknown as ReportReport;

const createGmp = () => ({
  session: createSession(),
});

describe('Summary', () => {
  test('renders basic task info, comment, hosts, filter and timezone', () => {
    const report = createBaseReport();
    const filter = createFilter('severity>5');
    const {render} = rendererWith({
      capabilities: true,
      gmp: createGmp(),
    });

    render(
      <Summary
        filter={filter}
        report={report}
        reportId={report.id as string}
      />,
    );

    const taskLink = screen.getAllByTestId('details-link')[0];
    expect(taskLink).toHaveAttribute('href', '/task/task-1');
    expect(taskLink).toHaveTextContent('Example Task');

    expect(screen.getByText('Example comment')).toBeInTheDocument();

    expect(screen.getByText('Hosts scanned')).toBeInTheDocument();
    expect(screen.getByText('4')).toBeInTheDocument();

    expect(screen.getByText('Results')).toBeInTheDocument();
    expect(screen.getByText('23')).toBeInTheDocument();

    expect(screen.getByText('Vulnerabilities')).toBeInTheDocument();
    expect(screen.getByText('6')).toBeInTheDocument();

    expect(screen.getByText('CVEs')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();

    expect(screen.getByText('Filter')).toBeInTheDocument();
    expect(screen.getByText('severity>5')).toBeInTheDocument();

    expect(screen.getByText('Timezone')).toBeInTheDocument();
    expect(screen.getByText('UTC (UTC)')).toBeInTheDocument();
  });

  test('shows error panel when reportError prop is provided', () => {
    const report = createBaseReport();
    const {render} = rendererWith({
      capabilities: true,
      gmp: createGmp(),
    });

    render(
      <Summary
        filter={createFilter('')}
        report={report}
        reportError={new Error('Load failed')}
        reportId={report.id as string}
      />,
    );

    expect(
      screen.getByText(/Error while loading Report report-1/),
    ).toBeInTheDocument();
  });
});
