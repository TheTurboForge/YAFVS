/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {
  fetchNativeTag,
  fetchNativeTagResources,
  fetchNativeTags,
} from 'gmp/native-api/tags';
import Filter from 'gmp/models/filter';
import {loadEntities, loadEntity} from 'web/store/entities/tags';
import {createState} from 'web/store/entities/utils/testing';
import {filterIdentifier} from 'web/store/utils';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API tags', () => {
  test('fetches tags as inherited Tag models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: '6d4dddf0-92a4-427f-b65d-bb9f9627aa01',
            name: 'Environment',
            comment: 'Operator label',
            owner: {name: 'admin'},
            resource_type: 'task',
            resource_count: 3,
            active: true,
            value: 'production',
            writable: true,
            permissions: ['get_tags', 'modify_tag'],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeTags(gmp, {
      page: 1,
      pageSize: 25,
      sort: 'name',
      filter: '',
      active: '1',
      resourceType: 'task',
      value: 'prod',
    });

    const tag = response.tags[0];
    expect(response.counts.filtered).toEqual(1);
    expect(tag.id).toEqual('6d4dddf0-92a4-427f-b65d-bb9f9627aa01');
    expect(tag.name).toEqual('Environment');
    expect(tag.comment).toEqual('Operator label');
    expect(tag.owner?.name).toEqual('admin');
    expect(tag.resourceType).toEqual('task');
    expect(tag.resourceCount).toEqual(3);
    expect(tag.value).toEqual('production');
    expect(tag.isActive()).toEqual(true);
    expect(tag.userCapabilities.mayEdit('tag')).toEqual(true);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/tags', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: '',
      active: '1',
      resource_type: 'task',
      value: 'prod',
    });
    expect(fetchMock).toHaveBeenCalledWith('https://turbovas.example/api/v1/tags', {
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        Authorization: 'Bearer jwt-token',
      },
    });
  });

  test('fetches tag detail metadata', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: '6d4dddf0-92a4-427f-b65d-bb9f9627aa01',
        name: 'Environment',
        resources: {type: 'target', count: {total: 1}},
        active: false,
        value: 'staging',
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const tag = await fetchNativeTag(
      gmp,
      '6d4dddf0-92a4-427f-b65d-bb9f9627aa01',
    );

    expect(tag.isActive()).toEqual(false);
    expect(tag.resourceType).toEqual('target');
    expect(tag.resourceCount).toEqual(1);
    expect(tag.value).toEqual('staging');
  });

  test('fetches assigned tag resources as generic models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        tag_id: '6d4dddf0-92a4-427f-b65d-bb9f9627aa01',
        resource_type: 'task',
        page: {page: 1, page_size: 40, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: 'task-1',
            type: 'task',
            name: 'Nightly scan',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const resources = await fetchNativeTagResources(
      gmp,
      '6d4dddf0-92a4-427f-b65d-bb9f9627aa01',
      'task',
      40,
    );

    expect(resources[0].id).toEqual('task-1');
    expect(resources[0].name).toEqual('Nightly scan');
    expect(resources[0].entityType).toEqual('task');
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/tags/6d4dddf0-92a4-427f-b65d-bb9f9627aa01/resources',
      {
        token: 'test-token',
        page: 1,
        page_size: 40,
        sort: 'name',
      },
    );
  });

  test('loads the tag store through same-origin native API', async () => {
    const filter = Filter.fromString(
      'first=1 rows=10 sort=name resource_type=task',
    );
    const rootState = createState('tag', {
      isLoading: {
        [filterIdentifier(filter)]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 10, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: '6d4dddf0-92a4-427f-b65d-bb9f9627aa01',
            name: 'Task label',
            resource_type: 'task',
            resource_count: 2,
            active: true,
            value: 'prod',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();

    await loadEntities(gmp)(filter)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/tags', {
      token: 'test-token',
      page: 1,
      page_size: 10,
      sort: 'name',
      filter: '',
      active: '',
      resource_type: 'task',
      value: '',
    });
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITIES_LOADING_SUCCESS');
    expect(successAction.counts.filtered).toEqual(1);
    expect(successAction.data[0].name).toEqual('Task label');
    expect(successAction.data[0].resourceType).toEqual('task');
  });

  test('loads tag detail store entries through same-origin native API', async () => {
    const id = '6d4dddf0-92a4-427f-b65d-bb9f9627aa01';
    const rootState = createState('tag', {
      isLoading: {
        [id]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id,
        name: 'Environment',
        resources: {type: 'task', count: {total: 3}},
        active: true,
        value: 'production',
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();

    await loadEntity(gmp)(id)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/tags/6d4dddf0-92a4-427f-b65d-bb9f9627aa01',
      {token: 'test-token'},
    );
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITY_LOADING_SUCCESS');
    expect(successAction.data.name).toEqual('Environment');
    expect(successAction.data.resourceCount).toEqual(3);
  });
});
