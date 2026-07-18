/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import CertBundAdv from 'gmp/models/cert-bund';
import Filter from 'gmp/models/filter';
import {
  fetchNativeCertBundAdvisory,
  fetchNativeCertBundAdvisories,
} from 'gmp/native-api/cert-bund-advisories';
import {loadEntities, loadEntity} from 'web/store/entities/certbund';
import {createState} from 'web/store/entities/utils/testing';
import {filterIdentifier} from 'web/store/utils';

const createGmp = ({
  jwt,
  token = 'test-token',
}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://yafvs.example/${path}`),
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
      'https://yafvs.example/api/v1/cert-bund-advisories',
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
        rich_detail: {
          description: ['Native XML-only description.'],
          reference_url: 'https://example.test/native-cert-bund',
          software: 'Native product',
        },
        created_at: '2026-06-18T20:00:00Z',
        modified_at: '2026-06-19T07:00:00Z',
        updated_at: '2026-06-19T07:00:00Z',
        user_tags: [
          {
            id: '4f1d4875-0a24-48bf-8eda-b1cb256a92cf',
            name: 'Native tag',
            value: 'true',
            comment: 'Native CERT-Bund tag',
          },
        ],
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
    expect(advisory.description).toEqual(['Native XML-only description.']);
    expect(advisory.referenceUrl).toEqual(
      'https://example.test/native-cert-bund',
    );
    expect(advisory.software).toEqual('Native product');
    expect(advisory.userTags).toHaveLength(1);
    expect(advisory.userTags[0].name).toEqual('Native tag');
    expect(advisory.userTags[0].value).toEqual('true');
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/cert-bund-advisories/CB-K14%2F0001',
      {token: 'test-token'},
    );
  });

  test('loads native catalog fields and rich detail without inherited get', async () => {
    const id = 'CB-K14/0001';
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
        rich_detail: {
          description: ['Native XML-only description.'],
          reference_url: 'https://example.test/native-cert-bund',
          software: 'Native product',
        },
        created_at: '2026-06-18T20:00:00Z',
        modified_at: '2026-06-19T07:00:00Z',
        user_tags: [
          {
            id: '4f1d4875-0a24-48bf-8eda-b1cb256a92cf',
            name: 'Native tag',
            value: 'true',
            comment: 'Native CERT-Bund tag',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      ...createGmp({jwt: 'jwt-token'}),
      certbund: {
        get: testing.fn(),
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
    expect(gmp.certbund.get).not.toHaveBeenCalled();
    expect(advisory).toBeInstanceOf(CertBundAdv);
    expect(advisory?.title).toEqual('Native title');
    expect(advisory?.summary).toEqual('Native summary');
    expect(advisory?.severity).toEqual(9.1);
    expect(advisory?.cve_refs).toEqual(2);
    expect(advisory?.cves).toEqual(['CVE-2026-10001', 'CVE-2026-10002']);
    expect(advisory?.description).toEqual(['Native XML-only description.']);
    expect(advisory?.referenceUrl).toEqual(
      'https://example.test/native-cert-bund',
    );
    expect(advisory?.software).toEqual('Native product');
    expect(advisory?.isWritable()).toEqual(true);
    expect(advisory?.userTags).toHaveLength(1);
    expect(advisory?.userTags?.[0].id).toEqual(
      '4f1d4875-0a24-48bf-8eda-b1cb256a92cf',
    );
    expect(advisory?.userTags?.[0].name).toEqual('Native tag');
    expect(advisory?.userTags?.[0].value).toEqual('true');
    expect(advisory?.userTags?.[0].comment).toEqual('Native CERT-Bund tag');
  });

  test('loads the CERT-Bund store through same-origin native API', async () => {
    const filter = Filter.fromString('first=1 rows=10 sort-reverse=created');
    const rootState = createState('certbund', {
      isLoading: {
        [filterIdentifier(filter)]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 10, total: 1, sort: '-created', filter: ''},
        items: [
          {
            id: 'cert-bund-uuid-1',
            name: 'CERT-Bund-2026-001',
            title: 'Example CERT-Bund advisory',
            summary: 'OpenSSL update advisory.',
            severity: 8.7,
            cve_refs: 2,
            cves: ['CVE-2026-10001', 'CVE-2026-10002'],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();

    await loadEntities(gmp)(filter)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/cert-bund-advisories', {
      token: 'test-token',
      page: 1,
      page_size: 10,
      sort: '-created',
      filter: '',
    });
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITIES_LOADING_SUCCESS');
    expect(successAction.counts.filtered).toEqual(1);
    expect(successAction.data[0].name).toEqual('CERT-Bund-2026-001');
    expect(successAction.data[0].cve_refs).toEqual(2);
  });
});
