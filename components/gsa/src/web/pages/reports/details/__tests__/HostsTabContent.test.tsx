/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import Filter from 'gmp/models/filter';
import {createSession} from 'gmp/testing';
import {SEVERITY_RATING_CVSS_3} from 'gmp/utils/severity';
import {rendererWith, screen} from 'web/testing';
import HostsTabContent from 'web/pages/reports/details/HostsTabContent';

const filter = Filter.fromString('first=1 rows=10 sort=host');
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
  settings: {
    severityRating: SEVERITY_RATING_CVSS_3,
  },
  session: createSession({token: 'test-token'}),
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('HostsTabContent', () => {
  test('should render native Hosts tab for regular reports', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 10, total: 1, sort: 'host', filter: ''},
        items: [
          {
            host: '192.0.2.10',
            hostname: 'host.example.test',
            best_os_txt: 'Debian GNU/Linux',
            ports_count: 5,
            applications_count: 3,
            authentication_state: 'Authenticated',
            start_time: '2024-01-15T10:00:00Z',
            end_time: '2024-01-15T10:05:00Z',
            result_count: 8,
            vulnerability_count: 2,
            severity: {
              critical: 0,
              high: 1,
              medium: 1,
              low: 0,
              log: 6,
              false_positive: 0,
            },
            max_severity: 7.5,
            source_report_id: reportId,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();
    const {render} = rendererWith({gmp, router: true});

    render(
      <HostsTabContent
        reportFilter={filter}
        reportId={reportId}
        status="Done"
      />,
    );

    expect(await screen.findByText('192.0.2.10')).toBeInTheDocument();
    expect(screen.getByText('host.example.test')).toBeInTheDocument();
    expect(screen.getByText('Debian GNU/Linux')).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/reports/report-123/hosts'),
      expect.objectContaining({credentials: 'include'}),
    );
  });

  test('should render fetch errors from the native Hosts endpoint', async () => {
    testing.stubGlobal(
      'fetch',
      testing.fn().mockResolvedValue({ok: false, status: 500}),
    );
    const gmp = createGmp();
    const {render} = rendererWith({gmp, router: true});

    render(
      <HostsTabContent
        reportFilter={filter}
        reportId={reportId}
        status="Done"
      />,
    );

    expect(
      await screen.findByText(/Native API request failed with status 500/),
    ).toBeInTheDocument();
  });
});
