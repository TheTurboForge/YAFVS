/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {rendererWith, screen, within} from 'web/testing';
import Filter from 'gmp/models/filter';
import {createSession} from 'gmp/testing';
import ErrorsTab from 'web/pages/reports/details/ErrorsTab';

const filter = Filter.fromString('first=1 rows=10');

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
  settings: {
    reloadInterval: 5000,
    reloadIntervalActive: 2000,
    reloadIntervalInactive: 10000,
  },
  session: createSession({token: 'test-token'}),
});

const reportId = 'report-123';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('ErrorsTab', () => {
  test('should render loading state initially', () => {
    testing.stubGlobal('fetch', testing.fn(() => new Promise(() => {})));
    const gmp = createGmp();
    const {render} = rendererWith({gmp, router: true, capabilities: true});

    render(<ErrorsTab filter={filter} reportId={reportId} status="Done" />);

    expect(screen.getByTestId('loading')).toBeInTheDocument();
  });

  test('should render native table with errors', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 10, total: 1, sort: '-created_at', filter: ''},
        items: [
          {
            id: 'result-1',
            host: '192.0.2.10',
            port: '456/tcp',
            nvt_oid: '1.3.6.1.4.1.25623.1.0.1',
            description: 'This is an error.',
            source_report_id: 'raw-report-1',
            created_at: '2026-06-18T10:00:00Z',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();
    const {render} = rendererWith({gmp, router: true, capabilities: true});

    render(<ErrorsTab filter={filter} reportId={reportId} status="Done" />);

    const table = await screen.findByRole('table');
    expect(table).toBeInTheDocument();

    const header = within(table).getAllByRole('columnheader');
    expect(header[0]).toHaveTextContent('Created');
    expect(header[1]).toHaveTextContent('Host');
    expect(header[2]).toHaveTextContent('Port');
    expect(header[3]).toHaveTextContent('NVT');
    expect(header[4]).toHaveTextContent('Description');
    expect(header[5]).toHaveTextContent('Raw Evidence');

    expect(screen.getByText('This is an error.')).toBeInTheDocument();
    expect(screen.getByText('192.0.2.10')).toBeInTheDocument();
    expect(screen.getByText('456/tcp')).toBeInTheDocument();
    expect(screen.getByText('result-1').closest('a')).toHaveAttribute(
      'href',
      '/result/result-1',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/reports/report-123/errors'),
      expect.objectContaining({credentials: 'include'}),
    );
  });

  test('should render empty native error table', async () => {
    testing.stubGlobal(
      'fetch',
      testing.fn().mockResolvedValue({
        json: testing.fn().mockResolvedValue({
          page: {page: 1, page_size: 10, total: 0, sort: '-created_at', filter: ''},
          items: [],
        }),
        ok: true,
        status: 200,
      }),
    );
    const gmp = createGmp();
    const {render} = rendererWith({gmp, router: true, capabilities: true});

    render(<ErrorsTab filter={filter} reportId={reportId} status="Done" />);

    expect(await screen.findByTestId('native-raw-report-errors-table')).toBeInTheDocument();
  });

  test('should render native fetch failure', async () => {
    testing.stubGlobal(
      'fetch',
      testing.fn().mockResolvedValue({ok: false, status: 500}),
    );
    const gmp = createGmp();
    const {render} = rendererWith({gmp, router: true, capabilities: true});

    render(<ErrorsTab filter={filter} reportId={reportId} status="Done" />);

    expect(
      await screen.findByText(/Native API request failed with status 500/),
    ).toBeInTheDocument();
  });
});
