/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {screen, rendererWith} from 'web/testing';
import Filter from 'gmp/models/filter';
import {createSession} from 'gmp/testing';
import {SEVERITY_RATING_CVSS_3} from 'gmp/utils/severity';
import PortsTab from 'web/pages/reports/details/PortsTab';

const reportFilter = Filter.fromString(
  'apply_overrides=0 levels=hml rows=2 min_qod=70 first=1 sort-reverse=severity',
);

const createGmp = () => ({
  buildUrl: testing.fn((path, params = {}) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
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
  session: createSession({token: 'test-token', username: 'admin'}),
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('Report Ports Tab tests', () => {
  test('should render Report Ports Tab', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 10,
          total: 2,
          sort: '-max_severity',
          filter: '',
        },
        items: [
          {
            port: '123/tcp',
            protocol: 'tcp',
            host_count: 1,
            result_count: 4,
            vulnerability_count: 2,
            max_severity: 10.0,
            source_report_ids: ['1234'],
          },
          {
            port: '456/tcp',
            protocol: 'tcp',
            host_count: 1,
            result_count: 2,
            vulnerability_count: 1,
            max_severity: 5.0,
            source_report_ids: ['1234'],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();
    const {render} = rendererWith({
      gmp,
      router: true,
    });

    const {baseElement} = render(
      <PortsTab reportFilter={reportFilter} reportId="1234" />,
    );

    expect(await screen.findByText('123/tcp')).toBeInTheDocument();

    const header = baseElement.querySelectorAll('th');
    const rows = baseElement.querySelectorAll('tr');
    const bars = screen.getAllByTestId('progressbar-box');

    // Headings
    expect(header[0]).toHaveTextContent('Port');
    expect(header[1]).toHaveTextContent('Protocol');
    expect(header[2]).toHaveTextContent('Hosts');
    expect(header[3]).toHaveTextContent('Results');
    expect(header[4]).toHaveTextContent('Vulnerabilities');
    expect(header[5]).toHaveTextContent('Severity');

    // Row 1
    expect(rows[1]).toHaveTextContent('123/tcptcp142');
    expect(bars[0]).toHaveAttribute('title', 'Critical');
    expect(bars[0]).toHaveTextContent('10.0 (Critical)');

    // Row 2
    expect(rows[2]).toHaveTextContent('456/tcptcp121');
    expect(bars[1]).toHaveAttribute('title', 'Medium');
    expect(bars[1]).toHaveTextContent('5.0 (Medium)');

    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/reports/1234/ports'),
      expect.objectContaining({credentials: 'include'}),
    );
  });
});
