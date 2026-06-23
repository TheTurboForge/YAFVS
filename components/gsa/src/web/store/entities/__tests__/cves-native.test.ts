/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {fetchNativeCve, fetchNativeCves} from 'gmp/native-api/cves';

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

describe('native API CVE catalog', () => {
  test('fetches top-level CVEs as inherited Cve models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 25,
          total: 1,
          sort: '-severity',
          filter: 'lightllm',
        },
        items: [
          {
            id: 'CVE-2026-26220',
            name: 'CVE-2026-26220',
            comment: '',
            description: 'LightLLM remote code execution vulnerability.',
            cvss_base_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            severity: 9.8,
            products: ['cpe:/a:example:lightllm:1.1.0'],
            epss: {score: 0.42, percentile: 0.91},
            published_at: '2026-06-18T20:00:00Z',
            modified_at: '2026-06-19T07:00:00Z',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeCves(gmp, {
      page: 1,
      pageSize: 25,
      sort: '-severity',
      filter: 'lightllm',
    });

    const cve = response.cves[0];
    expect(response.counts.filtered).toEqual(1);
    expect(cve.id).toEqual('CVE-2026-26220');
    expect(cve.name).toEqual('CVE-2026-26220');
    expect(cve.description).toEqual(
      'LightLLM remote code execution vulnerability.',
    );
    expect(cve.cvssBaseVector).toEqual(
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    );
    expect(cve.severity).toEqual(9.8);
    expect(cve.products).toEqual(['cpe:/a:example:lightllm:1.1.0']);
    expect(cve.epss?.score).toEqual(0.42);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/cves', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: '-severity',
      filter: 'lightllm',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/cves',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('fetches one CVE detail through the native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'CVE-2026-26220',
        name: 'CVE-2026-26220',
        description: 'LightLLM remote code execution vulnerability.',
        cvss_base_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        severity: 9.8,
        products: [],
        cert_refs: [
          {
            name: 'CB-K26/0001',
            title: 'Example CERT-Bund advisory',
            type: 'CERT-Bund',
          },
        ],
        nvt_refs: [
          {
            id: '1.3.6.1.4.1.25623.1.0.900001',
            name: 'Example vulnerability test',
          },
        ],
        user_tags: [
          {
            id: 'a01cce79-9ad3-4714-903d-893a333ab33d',
            name: 'Native tag',
            value: 'true',
            comment: 'Native CVE tag',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();

    const cve = await fetchNativeCve(gmp, 'CVE-2026-26220');

    expect(cve.id).toEqual('CVE-2026-26220');
    expect(cve.certs).toEqual([
      {
        cert_type: 'CERT-Bund',
        name: 'CB-K26/0001',
        title: 'Example CERT-Bund advisory',
      },
    ]);
    expect(cve.nvts).toEqual([
      {
        id: '1.3.6.1.4.1.25623.1.0.900001',
        name: 'Example vulnerability test',
        oid: '1.3.6.1.4.1.25623.1.0.900001',
      },
    ]);
    expect(cve.userTags).toHaveLength(1);
    expect(cve.userTags[0].id).toEqual('a01cce79-9ad3-4714-903d-893a333ab33d');
    expect(cve.userTags[0].name).toEqual('Native tag');
    expect(cve.userTags[0].value).toEqual('true');
    expect(cve.userTags[0].comment).toEqual('Native CVE tag');
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/cves/CVE-2026-26220', {
      token: 'test-token',
    });
  });
});
