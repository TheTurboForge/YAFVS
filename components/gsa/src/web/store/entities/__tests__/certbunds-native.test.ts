/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import CertBundAdv from 'gmp/models/cert-bund';
import {
  fetchNativeCertBundAdvisory,
  fetchNativeCertBundAdvisories,
} from 'gmp/native-api/cert-bund-advisories';
import {loadEntity} from 'web/store/entities/certbund';

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

describe('native API CERT-Bund advisory catalog', () => {
  test('fetches top-level CERT-Bund advisories as inherited models', async () => {
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
            id: 'cert-bund-uuid-1',
            name: 'CERT-Bund-2026-001',
            comment: 'operator note',
            title: 'Example CERT-Bund advisory',
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

    const response = await fetchNativeCertBundAdvisories(gmp, {
      page: 1,
      pageSize: 25,
      sort: '-created',
      filter: 'openssl',
    });

    const advisory = response.certbunds[0];
    expect(response.counts.filtered).toEqual(1);
    expect(advisory.id).toEqual('cert-bund-uuid-1');
    expect(advisory.name).toEqual('CERT-Bund-2026-001');
    expect(advisory.comment).toEqual('operator note');
    expect(advisory.title).toEqual('Example CERT-Bund advisory');
    expect(advisory.summary).toEqual('OpenSSL update advisory.');
    expect(advisory.severity).toEqual(8.7);
    expect(advisory.cve_refs).toEqual(2);
    expect(advisory.cves).toEqual(['CVE-2026-10001', 'CVE-2026-10002']);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/cert-bund-advisories', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: '-created',
      filter: 'openssl',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/cert-bund-advisories',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('fetches one CERT-Bund advisory from the native detail endpoint', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'cert-bund-uuid-1',
        name: 'CB-K14/0001',
        comment: 'operator note',
        title: 'Native CERT-Bund advisory',
        summary: 'Native summary.',
        severity: 9.1,
        cve_refs: 1,
        cves: ['CVE-2026-10001'],
        created_at: '2026-06-18T20:00:00Z',
        modified_at: '2026-06-19T07:00:00Z',
        updated_at: '2026-06-19T07:00:00Z',
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeCertBundAdvisory(gmp, 'CB-K14/0001');

    const advisory = response.certbund;
    expect(advisory.id).toEqual('cert-bund-uuid-1');
    expect(advisory.name).toEqual('CB-K14/0001');
    expect(advisory.title).toEqual('Native CERT-Bund advisory');
    expect(advisory.summary).toEqual('Native summary.');
    expect(advisory.severity).toEqual(9.1);
    expect(advisory.cves).toEqual(['CVE-2026-10001']);
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/cert-bund-advisories/CB-K14%2F0001',
      {token: 'test-token'},
    );
  });

  test('loads native catalog fields while preserving inherited rich detail', async () => {
    const id = 'CB-K14/0001';
    const inherited = CertBundAdv.fromElement({
      _id: id,
      writable: 1,
      cert_bund_adv: {
        severity: 3.1,
        cve_refs: 1,
        title: 'Inherited title',
        summary: 'Inherited summary',
        raw_data: {
          Advisory: {
            CVEList: {CVE: ['CVE-2026-00001']},
            Description: {
              Element: [{TextBlock: 'Inherited XML-only description.'}],
            },
            Reference_URL: 'https://example.test/inherited-cert-bund',
            Software: 'Inherited product',
          },
        },
      },
      user_tags: {
        tag: [{_id: 'tag-1', name: 'Retained tag', value: 'true'}],
      },
    });
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id,
        name: 'CB-K14/0001',
        comment: 'native comment',
        title: 'Native title',
        summary: 'Native summary',
        severity: 9.1,
        cve_refs: 2,
        cves: ['CVE-2026-10001', 'CVE-2026-10002'],
        created_at: '2026-06-18T20:00:00Z',
        modified_at: '2026-06-19T07:00:00Z',
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      ...createGmp({jwt: 'jwt-token'}),
      certbund: {
        get: testing.fn().mockResolvedValue({data: inherited}),
      },
    };
    const actions: Array<{type: string; data?: CertBundAdv}> = [];
    const dispatch = testing.fn(action => {
      actions.push(action);
      return action;
    });
    const getState = () => ({
      entities: {
        certbund: {
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
    expect(gmp.certbund.get).toHaveBeenCalledWith({id});
    expect(advisory).toBeInstanceOf(CertBundAdv);
    expect(advisory?.title).toEqual('Native title');
    expect(advisory?.summary).toEqual('Native summary');
    expect(advisory?.severity).toEqual(9.1);
    expect(advisory?.cve_refs).toEqual(2);
    expect(advisory?.cves).toEqual(['CVE-2026-10001', 'CVE-2026-10002']);
    expect(advisory?.description).toEqual([
      'Inherited XML-only description.',
    ]);
    expect(advisory?.referenceUrl).toEqual(
      'https://example.test/inherited-cert-bund',
    );
    expect(advisory?.software).toEqual('Inherited product');
    expect(advisory?.isWritable()).toEqual(true);
    expect(advisory?.userTags?.[0].name).toEqual('Retained tag');
  });
});
