/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import Filter from 'gmp/models/filter';
import {fetchNativeCpe, fetchNativeCpes} from 'gmp/native-api/cpes';
import {loadEntities, loadEntity} from 'web/store/entities/cpes';
import {createState} from 'web/store/entities/utils/testing';
import {filterIdentifier} from 'web/store/utils';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API CPE catalog', () => {
  test('fetches top-level CPEs as inherited Cpe models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: '-modified', filter: 'lightllm'},
        items: [
          {
            id: 'cpe:/a:example:lightllm:1.1.0',
            name: 'cpe:/a:example:lightllm:1.1.0',
            comment: '',
            title: 'Example LightLLM 1.1.0',
            cpe_name_id: 'ABC-123',
            deprecated: false,
            severity: 9.8,
            cve_refs: 1,
            cves: [],
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

    const response = await fetchNativeCpes(gmp, {
      page: 1,
      pageSize: 25,
      sort: '-modified',
      filter: 'lightllm',
    });

    const cpe = response.cpes[0];
    expect(response.counts.filtered).toEqual(1);
    expect(cpe.id).toEqual('cpe:/a:example:lightllm:1.1.0');
    expect(cpe.name).toEqual('cpe:/a:example:lightllm:1.1.0');
    expect(cpe.title).toEqual('Example LightLLM 1.1.0');
    expect(cpe.cpeNameId).toEqual('ABC-123');
    expect(cpe.deprecated).toEqual(false);
    expect(cpe.severity).toEqual(9.8);
    expect(cpe.cveRefs).toEqual(1);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/cpes', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: '-modified',
      filter: 'lightllm',
    });
    expect(fetchMock).toHaveBeenCalledWith('https://turbovas.example/api/v1/cpes', {
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        Authorization: 'Bearer jwt-token',
      },
    });
  });

  test('fetches one CPE detail through the native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'cpe:/a:example:lightllm:1.1.0',
        name: 'cpe:/a:example:lightllm:1.1.0',
        title: 'Example LightLLM 1.1.0',
        deprecated: true,
        deprecated_by: 'cpe:/a:example:lightllm:1.2.0',
        cve_refs: 1,
        cves: [{id: 'CVE-2026-26220', severity: 9.8}],
        references: [{url: 'https://example.test/cpe'}],
        user_tags: [
          {
            id: '7523f0c6-bf41-42b2-b92f-441776f777ac',
            name: 'Native tag',
            value: 'true',
            comment: 'Native CPE tag',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();

    const cpe = await fetchNativeCpe(gmp, 'cpe:/a:example:lightllm:1.1.0');

    expect(cpe.id).toEqual('cpe:/a:example:lightllm:1.1.0');
    expect(cpe.deprecated).toEqual(true);
    expect(cpe.deprecatedBy).toEqual('cpe:/a:example:lightllm:1.2.0');
    expect(cpe.cves).toEqual([{id: 'CVE-2026-26220', severity: 9.8}]);
    expect(cpe.references).toEqual([
      {text: 'https://example.test/cpe', url: 'https://example.test/cpe'},
    ]);
    expect(cpe.userTags).toHaveLength(1);
    expect(cpe.userTags[0].id).toEqual('7523f0c6-bf41-42b2-b92f-441776f777ac');
    expect(cpe.userTags[0].name).toEqual('Native tag');
    expect(cpe.userTags[0].value).toEqual('true');
    expect(cpe.userTags[0].comment).toEqual('Native CPE tag');
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/cpes/cpe%3A%2Fa%3Aexample%3Alightllm%3A1.1.0',
      {token: 'test-token'},
    );
  });

  test('loads the CPE store through same-origin native API', async () => {
    const filter = Filter.fromString('first=1 rows=10 sort-reverse=modified');
    const rootState = createState('cpe', {
      isLoading: {
        [filterIdentifier(filter)]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 10, total: 1, sort: '-modified', filter: ''},
        items: [
          {
            id: 'cpe:/a:example:lightllm:1.1.0',
            title: 'Example LightLLM 1.1.0',
            severity: 9.8,
            cve_refs: 1,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();

    await loadEntities(gmp)(filter)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/cpes', {
      token: 'test-token',
      page: 1,
      page_size: 10,
      sort: '-modified',
      filter: '',
    });
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITIES_LOADING_SUCCESS');
    expect(successAction.counts.filtered).toEqual(1);
    expect(successAction.data[0].title).toEqual('Example LightLLM 1.1.0');
    expect(successAction.data[0].cveRefs).toEqual(1);
  });

  test('loads CPE detail store entries through same-origin native API', async () => {
    const id = 'cpe:/a:example:lightllm:1.1.0';
    const rootState = createState('cpe', {
      isLoading: {
        [id]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id,
        title: 'Example LightLLM 1.1.0',
        deprecated: true,
        cve_refs: 1,
        cves: [{id: 'CVE-2026-26220', severity: 9.8}],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();

    await loadEntity(gmp)(id)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/cpes/cpe%3A%2Fa%3Aexample%3Alightllm%3A1.1.0',
      {token: 'test-token'},
    );
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITY_LOADING_SUCCESS');
    expect(successAction.data.title).toEqual('Example LightLLM 1.1.0');
    expect(successAction.data.cves).toEqual([
      {id: 'CVE-2026-26220', severity: 9.8},
    ]);
  });
});
