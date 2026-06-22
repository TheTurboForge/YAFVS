/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {fetchNativeVulnerabilities} from 'gmp/native-api/vulnerabilities';

const createGmp = ({
  jwt,
  token = 'test-token',
}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API vulnerabilities list', () => {
  test('fetches top-level vulnerabilities as inherited Vulnerability models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: '-severity', filter: ''},
        items: [
          {
            id: '1.3.6.1.4.1.25623.1.0.900001',
            name: 'Example vulnerability',
            family: 'General',
            oldest_result: '2026-06-18T18:00:00Z',
            newest_result: '2026-06-18T20:00:00Z',
            severity: 7.5,
            qod: 80,
            result_count: 3,
            host_count: 2,
            cves: ['CVE-2026-0001'],
            cert_refs: ['dfn-cert:DFN-CERT-2026-0001'],
            xrefs: ['url:https://example.test/advisory'],
            max_epss: {
              score: 0.91,
              percentile: 0.98,
              cve: 'CVE-2026-0001',
              severity: 7.5,
            },
            max_severity: {
              score: 0.42,
              percentile: 0.77,
              cve: 'CVE-2026-0002',
              severity: 9.8,
            },
            summary: 'Native vulnerability summary',
            insight: 'Native insight',
            affected: 'Native affected package',
            impact: 'Native impact',
            detection: 'Native detection method',
            solution_type: 'VendorFix',
            solution: 'Install the vendor fix.',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeVulnerabilities(gmp, {
      page: 1,
      pageSize: 25,
      sort: '-severity',
      filter: '',
    });

    const vulnerability = response.vulnerabilities[0];
    expect(response.counts.filtered).toEqual(1);
    expect(vulnerability.id).toEqual('1.3.6.1.4.1.25623.1.0.900001');
    expect(vulnerability.name).toEqual('Example vulnerability');
    expect(vulnerability.family).toEqual('General');
    expect(vulnerability.severity).toEqual(7.5);
    expect(vulnerability.qod).toEqual(80);
    expect(vulnerability.results?.count).toEqual(3);
    expect(vulnerability.hosts?.count).toEqual(2);
    expect(vulnerability.cves).toEqual(['CVE-2026-0001']);
    expect(vulnerability.certs[0]).toEqual({
      id: 'DFN-CERT-2026-0001',
      type: 'dfn-cert',
    });
    expect(vulnerability.xrefs[0]).toEqual({
      ref: 'https://example.test/advisory',
      type: 'url',
    });
    expect(vulnerability.epss?.maxEpss?.score).toEqual(0.91);
    expect(vulnerability.epss?.maxSeverity?.cve?.severity).toEqual(9.8);
    expect(vulnerability.summary).toEqual('Native vulnerability summary');
    expect(vulnerability.solution?.type).toEqual('VendorFix');
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/vulnerabilities', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: '-severity',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/vulnerabilities',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('maps native page offsets into inherited pagination counts', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 2,
          page_size: 25,
          total: 533,
          sort: '-severity',
          filter: '',
        },
        items: [
          {
            id: '1.3.6.1.4.1.25623.1.0.900026',
            name: 'Second page vulnerability',
            severity: 8.1,
            qod: 90,
            result_count: 1,
            host_count: 1,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);

    const response = await fetchNativeVulnerabilities(createGmp(), {
      page: 2,
      pageSize: 25,
      sort: '-severity',
      filter: '',
    });

    expect(response.counts.first).toEqual(26);
    expect(response.counts.last).toEqual(26);
    expect(response.counts.filtered).toEqual(533);
    expect(response.counts.hasPrevious()).toEqual(true);
    expect(response.counts.hasNext()).toEqual(true);
  });
});
