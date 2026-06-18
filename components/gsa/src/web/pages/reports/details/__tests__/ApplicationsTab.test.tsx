/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {rendererWith, screen, within} from 'web/testing';
import Filter from 'gmp/models/filter';
import {createSession} from 'gmp/testing';
import ApplicationsTab from 'web/pages/reports/details/ApplicationsTab';

const filter = Filter.fromString('first=1 rows=10');
const reportId = 'report-123';

const createGmp = () => ({
  buildUrl: testing.fn((path: string, params?: Record<string, unknown>) => {
    const query = new URLSearchParams();
    Object.entries(params ?? {}).forEach(([key, value]) => {
      if (value !== undefined) {
        query.set(key, String(value));
      }
    });
    return `https://turbovas.example/${path}${
      query.size > 0 ? `?${query.toString()}` : ''
    }`;
  }),
  settings: {severityRating: 'CVSSv3'},
  session: createSession({token: 'test-token'}),
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('ApplicationsTab', () => {
  test('should render loading state initially', () => {
    testing.stubGlobal('fetch', testing.fn(() => new Promise(() => {})));
    const {render} = rendererWith({gmp: createGmp(), router: true});

    render(
      <ApplicationsTab filter={filter} reportId={reportId} status={'Done'} />,
    );

    expect(screen.getByTestId('loading')).toBeInTheDocument();
  });

  test('should render native report applications table', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 10, total: 2, sort: 'name', filter: ''},
        items: [
          {
            name: 'Apache HTTP Server',
            version: '',
            cpe: 'cpe:/a:apache:http_server',
            host_count: 10,
            result_count: 250,
            vulnerability_count: 8,
            max_severity: 10.0,
            source_report_ids: [reportId],
          },
          {
            name: 'Nginx',
            version: '',
            cpe: 'cpe:/a:nginx:nginx',
            host_count: 3,
            result_count: 15,
            vulnerability_count: 2,
            max_severity: 5.0,
            source_report_ids: [reportId],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const {render} = rendererWith({gmp: createGmp(), router: true});

    render(
      <ApplicationsTab filter={filter} reportId={reportId} status={'Done'} />,
    );

    const table = await screen.findByTestId('native-raw-report-applications-table');
    const rows = within(table).getAllByRole('row');
    expect(rows[0]).toHaveTextContent('Application');
    expect(rows[0]).toHaveTextContent('CPE');
    expect(rows[0]).toHaveTextContent('Max Severity');
    expect(rows[1]).toHaveTextContent('Apache HTTP Server');
    expect(rows[1]).toHaveTextContent('10');
    expect(rows[1]).toHaveTextContent('250');
    expect(rows[2]).toHaveTextContent('Nginx');
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/reports/report-123/applications'),
      expect.objectContaining({credentials: 'include'}),
    );
  });

  test('should render native fetch failure', async () => {
    testing.stubGlobal(
      'fetch',
      testing.fn().mockResolvedValue({ok: false, status: 500}),
    );
    const {render} = rendererWith({gmp: createGmp(), router: true});

    render(
      <ApplicationsTab filter={filter} reportId={reportId} status={'Done'} />,
    );

    expect(
      await screen.findByText(/Native API request failed with status 500/),
    ).toBeInTheDocument();
  });
});
