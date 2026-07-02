/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {rendererWith, screen, waitFor, within} from 'web/testing';
import Filter from 'gmp/models/filter';
import {createSession} from 'gmp/testing';
import CvesTab from 'web/pages/reports/details/CvesTab';

const filter = Filter.fromString(
  'apply_overrides=0 levels=hml rows=2 min_qod=70 first=1 sort-reverse=severity',
);

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
  settings: {
    severityRating: 'CVSSv3',
  },
  session: createSession({token: 'test-token'}),
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('Report CVEs Tab tests', () => {
  test('should render loading state initially', () => {
    testing.stubGlobal('fetch', testing.fn(() => new Promise(() => {})));
    const gmp = createGmp();
    const {render} = rendererWith({gmp, router: true, capabilities: true});

    render(<CvesTab filter={filter} reportId={reportId} status="Done" />);

    expect(screen.getByTestId('loading')).toBeInTheDocument();
  });

  test('should render native Report CVEs Tab', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 2, total: 1, sort: '-max_severity', filter: ''},
        items: [
          {
            id: 'CVE-2019-1234',
            affected_system_count: 2,
            result_count: 3,
            max_severity: 7.5,
            source_report_ids: [reportId],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();
    const {render} = rendererWith({gmp, router: true, capabilities: true});
    render(<CvesTab filter={filter} reportId={reportId} status="Done" />);

    const table = await screen.findByRole('table');
    const headers = within(table).getAllByRole('columnheader');
    expect(headers[0]).toHaveTextContent('CVE');
    expect(headers[1]).toHaveTextContent('Max Severity');
    expect(headers[2]).toHaveTextContent('Affected Systems');
    expect(headers[3]).toHaveTextContent('Results');

    const cveLink = screen.getByText('CVE-2019-1234');
    expect(cveLink.closest('a')).toHaveAttribute('href', '/cve/CVE-2019-1234');
    expect(screen.getByText('2')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/reports/report-123/cves'),
      expect.objectContaining({credentials: 'include'}),
    );
  });

  test('should keep native CVE query pagination and sort in sync', async () => {
    const interactiveFilter = Filter.fromString(
      'search=postgres rows=2 first=3 sort-reverse=severity',
    );
    const fetchMock = testing.fn((url: string) => {
      const params = new URL(url).searchParams;
      const page = Number(params.get('page') ?? '1');
      const sort = params.get('sort') ?? '';
      const filterText = params.get('filter') ?? '';
      return Promise.resolve({
        json: testing.fn().mockResolvedValue({
          page: {
            page,
            page_size: Number(params.get('page_size') ?? '2'),
            total: 5,
            sort,
            filter: filterText,
          },
          items: [
            {
              id: `CVE-2019-${page}${sort === 'id' ? '999' : '123'}`,
              affected_system_count: 2,
              result_count: 3,
              max_severity: 7.5,
              source_report_ids: [reportId],
            },
          ],
        }),
        ok: true,
        status: 200,
      });
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();
    const {render} = rendererWith({gmp, router: true, capabilities: true});
    const {userEvent} = render(
      <CvesTab filter={interactiveFilter} reportId={reportId} status="Done" />,
    );

    await screen.findByText('CVE-2019-2123');
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/reports/report-123/cves',
      expect.objectContaining({
        page: 2,
        page_size: 2,
        sort: '-max_severity',
        filter: 'postgres',
      }),
    );
    expect(screen.getByText(/Page 2 of 3/)).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', {name: 'Next'}));
    await waitFor(() => {
      expect(gmp.buildUrl).toHaveBeenCalledWith(
        'api/v1/reports/report-123/cves',
        expect.objectContaining({
          page: 3,
          page_size: 2,
          sort: '-max_severity',
          filter: 'postgres',
        }),
      );
    });
    expect(await screen.findByText('CVE-2019-3123')).toBeInTheDocument();

    await userEvent.click(screen.getByText('CVE'));
    await waitFor(() => {
      expect(gmp.buildUrl).toHaveBeenCalledWith(
        'api/v1/reports/report-123/cves',
        expect.objectContaining({
          page: 1,
          page_size: 2,
          sort: 'id',
          filter: 'postgres',
        }),
      );
    });
    expect(await screen.findByText('CVE-2019-1999')).toBeInTheDocument();
  });

  test('should render empty native CVE table', async () => {
    testing.stubGlobal(
      'fetch',
      testing.fn().mockResolvedValue({
        json: testing.fn().mockResolvedValue({
          page: {page: 1, page_size: 2, total: 0, sort: '-max_severity', filter: ''},
          items: [],
        }),
        ok: true,
        status: 200,
      }),
    );
    const gmp = createGmp();
    const {render} = rendererWith({gmp, router: true, capabilities: true});

    render(<CvesTab filter={filter} reportId={reportId} status="Done" />);

    expect(await screen.findByTestId('native-raw-report-cves-table')).toBeInTheDocument();
  });

  test('should render native fetch failure', async () => {
    testing.stubGlobal(
      'fetch',
      testing.fn().mockResolvedValue({ok: false, status: 500}),
    );
    const gmp = createGmp();
    const {render} = rendererWith({gmp, router: true, capabilities: true});

    render(<CvesTab filter={filter} reportId={reportId} status="Done" />);

    expect(
      await screen.findByText(/Native API request failed with status 500/),
    ).toBeInTheDocument();
  });
});
