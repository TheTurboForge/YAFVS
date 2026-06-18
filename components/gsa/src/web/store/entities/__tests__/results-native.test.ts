/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {fetchNativeResults} from 'gmp/native-api/reports';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API result list', () => {
  test('fetches top-level results as inherited Result models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: '-severity', filter: ''},
        items: [
          {
            id: 'result-1',
            host: '192.168.178.42',
            host_asset_id: 'host-asset-1',
            hostname: 'workstation.local',
            port: '443/tcp',
            nvt_oid: '1.3.6.1.4.1.25623.1.0.900001',
            name: 'Example vulnerability',
            nvt_family: 'General',
            description_excerpt: 'Example detection text',
            solution_type: 'VendorFix',
            solution: 'Install the vendor fix.',
            severity: 7.5,
            qod: 80,
            scan_nvt_version: '20260618T1200',
            created_at: '2026-06-18T20:00:00Z',
            report: {id: 'report-1', name: 'Full and fast'},
            task: {id: 'task-1', name: 'LAN scan'},
            source_report_id: 'report-1',
            raw_evidence_href: '/report/report-1/result/result-1',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeResults(gmp, {
      page: 1,
      pageSize: 25,
      sort: '-severity',
      filter: '',
    });

    const result = response.results[0];
    expect(response.counts.filtered).toEqual(1);
    expect(result.id).toEqual('result-1');
    expect(result.name).toEqual('Example vulnerability');
    expect(result.severity).toEqual(7.5);
    expect(result.qod?.value).toEqual(80);
    expect(result.host?.name).toEqual('192.168.178.42');
    expect(result.host?.id).toEqual('host-asset-1');
    expect(result.host?.hostname).toEqual('workstation.local');
    expect(result.port).toEqual('443/tcp');
    expect(result.information?.id).toEqual('1.3.6.1.4.1.25623.1.0.900001');
    expect(result.information?.name).toEqual('Example vulnerability');
    expect((result.information as {solution?: {type?: string}})?.solution?.type).toEqual('VendorFix');
    expect(result.report?.id).toEqual('report-1');
    expect(result.task?.id).toEqual('task-1');
    expect(result.scan_nvt_version).toEqual('20260618T1200');
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/results', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: '-severity',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/results',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });
});
