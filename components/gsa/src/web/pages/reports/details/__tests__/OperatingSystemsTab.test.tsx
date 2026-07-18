/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {rendererWith, screen, within} from 'web/testing';
import Filter from 'gmp/models/filter';
import {createSession} from 'gmp/testing';
import OperatingSystemsTab from 'web/pages/reports/details/OperatingSystemsTab';

const filter = Filter.fromString('rows=2 first=1 sort=severity');
const reportId = 'report-123';

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
  settings: {severityRating: 'CVSSv3'},
  session: createSession({token: 'test-token'}),
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('Report Operating Systems Tab tests', () => {
  test('should render native Report Operating Systems Tab', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 2,
          total: 2,
          sort: 'max_severity',
          filter: '',
        },
        items: [
          {
            name: 'Foo OS',
            cpe: 'cpe:/foo/bar',
            host_count: 2,
            result_count: 7,
            vulnerability_count: 3,
            max_severity: 8.0,
            source_report_ids: [reportId],
          },
          {
            name: 'Lorem OS',
            cpe: 'cpe:/lorem/ipsum',
            host_count: 5,
            result_count: 11,
            vulnerability_count: 4,
            max_severity: 6.0,
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
      <OperatingSystemsTab filter={filter} reportId={reportId} status="Done" />,
    );

    const table = await screen.findByTestId(
      'native-raw-report-operating-systems-table',
    );
    const rows = within(table).getAllByRole('row');
    expect(rows[0]).toHaveTextContent('Operating System');
    expect(rows[0]).toHaveTextContent('CPE');
    expect(rows[0]).toHaveTextContent('Max Severity');
    expect(rows[1]).toHaveTextContent('Foo OS');
    expect(rows[1]).toHaveTextContent('cpe:/foo/bar');
    expect(rows[2]).toHaveTextContent('Lorem OS');
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/reports/report-123/operating-systems'),
      expect.objectContaining({credentials: 'include'}),
    );
  });

  test('should show loading state before data arrives', () => {
    testing.stubGlobal(
      'fetch',
      testing.fn(() => new Promise(() => {})),
    );
    const {render} = rendererWith({gmp: createGmp(), router: true});
    render(
      <OperatingSystemsTab filter={filter} reportId={reportId} status="Done" />,
    );

    expect(screen.getByTestId('loading')).toBeInTheDocument();
  });
});
