/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {rendererWith, screen, within} from 'web/testing';
import Filter from 'gmp/models/filter';
import {createSession} from 'gmp/testing';
import TLSCertificatesTab from 'web/pages/reports/details/TlsCertificatesTab';

const filter = Filter.fromString('rows=3 first=1 sort-reverse=notvalidafter');
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

describe('Report TLS Certificates Tab tests', () => {
  test('should render native Report TLS Certificates Tab', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 3, total: 1, sort: '-not_after', filter: ''},
        items: [
          {
            id: 'cert-1',
            fingerprint_sha256: 'abc123',
            subject: 'CN=LoremIpsumSubject1 C=Dolor',
            issuer: 'CN=Issuer C=Dolor',
            serial: '00B49C541FF5A8E1D9',
            not_before: '2019-08-10T00:00:00Z',
            not_after: '2019-09-10T00:00:00Z',
            host_count: 2,
            port_count: 3,
            result_count: 4,
            source_report_ids: [reportId],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const {render} = rendererWith({router: true, gmp: createGmp()});

    render(
      <TLSCertificatesTab
        reportFilter={filter}
        reportId={reportId}
        status="Done"
        onTlsCertificateDownloadClick={testing.fn()}
      />,
    );

    const table = await screen.findByTestId(
      'native-raw-report-tls-certificates-table',
    );
    const rows = within(table).getAllByRole('row');
    expect(rows[0]).toHaveTextContent('Subject DN');
    expect(rows[0]).toHaveTextContent('Issuer DN');
    expect(rows[0]).toHaveTextContent('Serial');
    expect(rows[1]).toHaveTextContent('CN=LoremIpsumSubject1 C=Dolor');
    expect(rows[1]).toHaveTextContent('CN=Issuer C=Dolor');
    expect(rows[1]).toHaveTextContent('00B49C541FF5A8E1D9');
    expect(rows[1]).toHaveTextContent('2');
    expect(rows[1]).toHaveTextContent('3');
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/reports/report-123/tls-certificates'),
      expect.objectContaining({credentials: 'include'}),
    );
  });

  test('should show loading state before data arrives', () => {
    testing.stubGlobal('fetch', testing.fn(() => new Promise(() => {})));
    const {render} = rendererWith({router: true, gmp: createGmp()});

    render(
      <TLSCertificatesTab
        reportFilter={filter}
        reportId={reportId}
        status="Done"
        onTlsCertificateDownloadClick={testing.fn()}
      />,
    );

    expect(screen.getByTestId('loading')).toBeInTheDocument();
  });
});
