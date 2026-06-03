/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, expect, test, testing} from '@gsa/testing';
import {rendererWith, screen} from 'web/testing';
import CollectionCounts from 'gmp/collection/collection-counts';
import Filter from 'gmp/models/filter';
import Result from 'gmp/models/result';
import {TASK_STATUS} from 'gmp/models/task';
import {createSession} from 'gmp/testing';
import ResultsTabContent from 'web/pages/reports/details/ResultsTabContent';

const filter = Filter.fromString('first=1 rows=10');

const createMockResult = (id = '101') => {
  return Result.fromElement({
    _id: id,
    name: 'CVE-2019-1234',
    host: {
      __text: '192.0.2.10',
      hostname: 'host.example.test',
    },
    port: '443/tcp',
    severity: 7.5,
    qod: {value: 80},
    creation_time: '2024-01-15T10:00:00Z',
    modification_time: '2024-01-15T10:00:00Z',
  });
};

const reportResultsCounts = new CollectionCounts({
  filtered: 1,
  all: 1,
  first: 1,
  rows: 10,
});

const results = [createMockResult()];
const resultsData = {
  entities: results,
  counts: reportResultsCounts,
};

const createGmp = ({
  get = testing.fn().mockResolvedValue(resultsData),
} = {}) => ({
  results: {
    get,
  },
  settings: {
    enableEPSS: false,
  },
  session: createSession({token: 'test-token'}),
});

describe('ResultsTabContent', () => {
  test('should render EmptyReport when the report has no results at all', () => {
    const reportResultsCounts = new CollectionCounts({
      filtered: 0,
      all: 0,
      first: 1,
      rows: 10,
    });

    const gmp = createGmp();
    const onTargetEditClick = testing.fn();
    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <ResultsTabContent
        hasTarget={true}
        progress={100}
        reportFilter={filter}
        reportId="report-123"
        reportResultsCounts={reportResultsCounts}
        status={TASK_STATUS.done}
        onFilterDecreaseMinQoDClick={testing.fn()}
        onFilterEditClick={testing.fn()}
        onFilterRemoveClick={testing.fn()}
        onTargetEditClick={onTargetEditClick}
      />,
    );

    expect(
      screen.getByText(/The scan did not collect any results/i),
    ).toBeInTheDocument();
  });

  test('should render EmptyResultsReport when all results are filtered out', () => {
    const reportResultsCounts = new CollectionCounts({
      filtered: 0,
      all: 5,
      first: 1,
      rows: 10,
    });

    const gmp = createGmp();
    const {render} = rendererWith({gmp});

    render(
      <ResultsTabContent
        hasTarget={true}
        progress={100}
        reportFilter={filter}
        reportId="report-123"
        reportResultsCounts={reportResultsCounts}
        status={TASK_STATUS.done}
        onFilterDecreaseMinQoDClick={testing.fn()}
        onFilterEditClick={testing.fn()}
        onFilterRemoveClick={testing.fn()}
        onTargetEditClick={testing.fn()}
      />,
    );

    expect(
      screen.getByText(
        /The report is empty. The filter does not match any of the 5 results./i,
      ),
    ).toBeInTheDocument();
  });

  test('should render ResultsTab for regular scans', () => {
    const gmp = createGmp();
    const {render} = rendererWith({gmp});

    render(
      <ResultsTabContent
        hasTarget={true}
        progress={100}
        reportFilter={filter}
        reportId="report-123"
        reportResultsCounts={reportResultsCounts}
        status={TASK_STATUS.done}
        onFilterDecreaseMinQoDClick={testing.fn()}
        onFilterEditClick={testing.fn()}
        onFilterRemoveClick={testing.fn()}
        onTargetEditClick={testing.fn()}
      />,
    );

    expect(screen.getByTestId('loading')).toBeInTheDocument();
  });
});
