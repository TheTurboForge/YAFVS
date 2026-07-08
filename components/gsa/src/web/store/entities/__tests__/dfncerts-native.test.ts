/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import DfnCertAdv from 'gmp/models/dfn-cert';
import {
  fetchNativeDfnCertAdvisory,
  fetchNativeDfnCertAdvisories,
} from 'gmp/native-api/dfn-cert-advisories';
import {loadEntity} from 'web/store/entities/dfncerts';

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

describe('native API DFN-CERT advisory catalog', () => {
  test('fetches top-level DFN-CERT advisories as inherited models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 25,
          total: 1,
          sort: '-created',
          filter: 'openssl',
        },
        items: [
          {
            id: 'dfn-uuid-1',
            name: 'DFN-CERT-2026-001',
            comment: 'operator note',
            title: 'Example DFN-CERT advisory',
            summary: 'OpenSSL update advisory.',
            severity: 8.7,
            cve_refs: 2,
            cves: ['CVE-2026-10001', 'CVE-2026-10002'],
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

    const response = await fetchNativeDfnCertAdvisories(gmp, {
      page: 1,
      pageSize: 25,
      sort: '-created',
      filter: 'openssl',
    });

    const advisory = response.dfncerts[0];
    expect(response.counts.filtered).toEqual(1);
    expect(advisory.id).toEqual('dfn-uuid-1');
    expect(advisory.name).toEqual('DFN-CERT-2026-001');
    expect(advisory.comment).toEqual('operator note');
    expect(advisory.title).toEqual('Example DFN-CERT advisory');
    expect(advisory.summary).toEqual('OpenSSL update advisory.');
    expect(advisory.severity).toEqual(8.7);
    expect(advisory.cve_refs).toEqual(2);
    expect(advisory.cves).toEqual(['CVE-2026-10001', 'CVE-2026-10002']);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/dfn-cert-advisories', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: '-created',
      filter: 'openssl',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/dfn-cert-advisories',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('fetches one DFN-CERT advisory from the native detail endpoint', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'dfn-uuid-1',
        name: 'DFN-CERT-2026-001',
        comment: 'operator note',
        title: 'Native DFN-CERT advisory',
        summary: 'Native summary.',
        severity: 9.1,
        cve_refs: 1,
        cves: ['CVE-2026-10001'],
        rich_detail: {
          links: [
            {
              href: 'https://example.test/native-dfn',
              rel: 'alternate',
            },
            {href: 'https://example.test/related-dfn'},
          ],
        },
        created_at: '2026-06-18T20:00:00Z',
        modified_at: '2026-06-19T07:00:00Z',
        updated_at: '2026-06-19T07:00:00Z',
        user_tags: [
          {
            id: '36e88138-bc32-4641-ab07-5d94a924965f',
            name: 'Native tag',
            value: 'true',
            comment: 'Native DFN-CERT tag',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeDfnCertAdvisory(
      gmp,
      'DFN-CERT-2026-001',
    );

    const advisory = response.dfncert;
    expect(advisory.id).toEqual('dfn-uuid-1');
    expect(advisory.name).toEqual('DFN-CERT-2026-001');
    expect(advisory.title).toEqual('Native DFN-CERT advisory');
    expect(advisory.summary).toEqual('Native summary.');
    expect(advisory.severity).toEqual(9.1);
    expect(advisory.cves).toEqual(['CVE-2026-10001']);
    expect(advisory.advisoryLink).toEqual('https://example.test/native-dfn');
    expect(advisory.additionalLinks).toEqual([
      'https://example.test/related-dfn',
    ]);
    expect(advisory.userTags).toHaveLength(1);
    expect(advisory.userTags[0].name).toEqual('Native tag');
    expect(advisory.userTags[0].value).toEqual('true');
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/dfn-cert-advisories/DFN-CERT-2026-001',
      {token: 'test-token'},
    );
  });

  test('loads native catalog fields and rich detail without inherited get', async () => {
    const id = 'DFN-CERT-2026-001';
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id,
        name: 'DFN-CERT-2026-001',
        comment: 'native comment',
        title: 'Native title',
        summary: 'Native summary',
        severity: 9.1,
        cve_refs: 2,
        cves: ['CVE-2026-10001', 'CVE-2026-10002'],
        rich_detail: {
          links: [
            {
              href: 'https://example.test/native-dfn',
              rel: 'alternate',
            },
            {href: 'https://example.test/related-dfn'},
          ],
        },
        created_at: '2026-06-18T20:00:00Z',
        modified_at: '2026-06-19T07:00:00Z',
        user_tags: [
          {
            id: '36e88138-bc32-4641-ab07-5d94a924965f',
            name: 'Native tag',
            value: 'true',
            comment: 'Native DFN-CERT tag',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      ...createGmp({jwt: 'jwt-token'}),
      dfncert: {
        get: testing.fn(),
      },
    };
    const actions: Array<{type: string; data?: DfnCertAdv}> = [];
    const dispatch = testing.fn(action => {
      actions.push(action);
      return action;
    });
    const getState = () => ({
      entities: {
        dfncert: {
          byId: {},
          errors: {},
          isLoading: {},
        },
      },
    });

    await loadEntity(gmp)(id)(dispatch, getState);

    const success = actions.find(
      action => action.type === 'ENTITY_LOADING_SUCCESS',
    );
    const advisory = success?.data;
    expect(gmp.dfncert.get).not.toHaveBeenCalled();
    expect(advisory).toBeInstanceOf(DfnCertAdv);
    expect(advisory?.title).toEqual('Native title');
    expect(advisory?.summary).toEqual('Native summary');
    expect(advisory?.severity).toEqual(9.1);
    expect(advisory?.cve_refs).toEqual(2);
    expect(advisory?.cves).toEqual(['CVE-2026-10001', 'CVE-2026-10002']);
    expect(advisory?.advisoryLink).toEqual(
      'https://example.test/native-dfn',
    );
    expect(advisory?.additionalLinks).toEqual([
      'https://example.test/related-dfn',
    ]);
    expect(advisory?.isWritable()).toEqual(true);
    expect(advisory?.userTags).toHaveLength(1);
    expect(advisory?.userTags?.[0].id).toEqual('36e88138-bc32-4641-ab07-5d94a924965f');
    expect(advisory?.userTags?.[0].name).toEqual('Native tag');
    expect(advisory?.userTags?.[0].value).toEqual('true');
    expect(advisory?.userTags?.[0].comment).toEqual('Native DFN-CERT tag');
  });
});
