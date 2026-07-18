/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {rendererWith, screen} from 'web/testing';
import CollectionCounts from 'gmp/collection/collection-counts';
import Filter from 'gmp/models/filter';
import {TASK_STATUS} from 'gmp/models/task';
import {createSession} from 'gmp/testing';
import ResultsTabContent from 'web/pages/reports/details/ResultsTabContent';

const filter = Filter.fromString('first=1 rows=10');

const reportResultsCounts = new CollectionCounts({
  filtered: 1,
  all: 1,
  first: 1,
  rows: 10,
});

const createGmp = () => ({
  buildUrl: testing.fn((path: string, params?: Record<string, unknown>) => {
    const query = new URLSearchParams();
    Object.entries(params ?? {}).forEach(([key, value]) => {
      if (value !== undefined) {
        query.set(key, String(value));
      }
    });
    return `https://yafvs.example/${path}${
      query.size > 0 ? `?${query.toString()}` : ''
    }`;
  }),
  settings: {
    enableEPSS: false,
  },
  session: createSession({token: 'test-token'}),
});

afterEach(() => {
  testing.unstubAllGlobals();
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

  test('should render native Results tab for regular scans', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 10, total: 1, sort: '-severity', filter: ''},
        items: [
          {
            id: 'result-1',
            host: '192.0.2.10',
            hostname: 'host.example.test',
            port: '443/tcp',
            nvt_oid: '1.3.6.1.4.1.25623.1.0.1',
            name: 'OpenSSH Vulnerability',
            nvt_family: 'General',
            severity: 7.5,
            qod: 80,
            created_at: '2024-01-15T10:00:00Z',
            source_report_id: 'report-123',
            raw_evidence_href: '/result/result-1',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
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
      await screen.findByText('OpenSSH Vulnerability'),
    ).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/reports/report-123/results'),
      expect.objectContaining({credentials: 'include'}),
    );
  });
});
