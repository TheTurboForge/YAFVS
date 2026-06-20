/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {fetchNativeNvts} from 'gmp/native-api/nvts';

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

describe('native API NVT catalog', () => {
  test('fetches top-level NVTs as inherited models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 25,
          total: 1,
          sort: '-created',
          filter: 'ssh',
        },
        items: [
          {
            id: '1.3.6.1.4.1.25623.1.0.10330',
            oid: '1.3.6.1.4.1.25623.1.0.10330',
            name: 'SSH Brute Force Logins With Default Credentials',
            family: 'Brute force attacks',
            severity: 7.5,
            qod: 80,
            qod_type: 'remote_banner',
            solution_type: 'Mitigation',
            solution_method: 'VendorFix',
            solution: 'Disable default credentials.',
            tags: 'summary=Finds weak SSH credentials.|impact=Login is possible.',
            cve_refs: 1,
            cves: ['CVE-2026-10001'],
            cert_refs: ['dfn-cert:DFN-CERT-2026-001'],
            xrefs: ['url:https://example.test/advisory'],
            max_epss: {
              score: 0.42,
              percentile: 0.91,
              cve: 'CVE-2026-10001',
              severity: 7.5,
            },
            max_severity: {
              score: 0.32,
              percentile: 0.81,
              cve: 'CVE-2026-10002',
              severity: 8.1,
            },
            created_at: '2026-06-18T20:00:00Z',
            modified_at: '2026-06-19T07:00:00Z',
            updated_at: '2026-06-19T07:00:00Z',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeNvts(gmp, {
      page: 1,
      pageSize: 25,
      sort: '-created',
      filter: 'ssh',
    });

    const nvt = response.nvts[0];
    expect(response.counts.filtered).toEqual(1);
    expect(nvt.id).toEqual('1.3.6.1.4.1.25623.1.0.10330');
    expect(nvt.name).toEqual('SSH Brute Force Logins With Default Credentials');
    expect(nvt.family).toEqual('Brute force attacks');
    expect(nvt.severity).toEqual(7.5);
    expect(nvt.qod?.value).toEqual(80);
    expect(nvt.qod?.type).toEqual('remote_banner');
    expect(nvt.solution?.type).toEqual('Mitigation');
    expect(nvt.solution?.description).toEqual('Disable default credentials.');
    expect(nvt.tags.summary).toEqual('Finds weak SSH credentials.');
    expect(nvt.cves).toEqual(['CVE-2026-10001']);
    expect(nvt.certs).toEqual([{id: 'DFN-CERT-2026-001', type: 'dfn-cert'}]);
    expect(nvt.xrefs).toEqual([
      {ref: 'https://example.test/advisory', type: 'url'},
    ]);
    expect(nvt.epss?.maxEpss?.score).toEqual(0.42);
    expect(nvt.epss?.maxSeverity?.cve?.id).toEqual('CVE-2026-10002');
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/nvts', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: '-created',
      filter: 'ssh',
    });
    expect(fetchMock).toHaveBeenCalledWith('https://turbovas.example/api/v1/nvts', {
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        Authorization: 'Bearer jwt-token',
      },
    });
  });
});
