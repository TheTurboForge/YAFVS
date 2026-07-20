/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import Filter from 'gmp/models/filter';
import {
  fetchNativeOverride,
  fetchNativeOverrides,
  nativeOverridesQueryFromFilter,
} from 'gmp/native-api/overrides';
import {loadEntities, loadEntity} from 'web/store/entities/overrides';
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

describe('native API overrides', () => {
  test('preserves exact task filters in native override-list requests', () => {
    const taskId = '12345678-1234-1234-1234-123456789abc';
    expect(
      nativeOverridesQueryFromFilter(
        Filter.fromString(`task_id=${taskId} rows=25 first=1`),
      ),
    ).toEqual({
      page: 1,
      pageSize: 25,
      sort: 'text',
      filter: '',
      active: '',
      text: '',
      taskName: '',
      taskId,
    });
  });

  test('fetches top-level overrides as inherited Override models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'text', filter: ''},
        items: [
          {
            id: '9f6c71ce-4f9c-41e2-8c8d-74b8a1aef001',
            owner: {name: 'admin'},
            nvt: {
              id: '1.3.6.1.4.1.25623.1.0.999999',
              name: 'Example NVT',
              type: 'nvt',
            },
            text: 'Accepted compensating control',
            text_excerpt: false,
            hosts: '192.0.2.10',
            port: '443/tcp',
            severity: 7.5,
            new_severity: -1,
            writable: true,
            in_use: false,
            orphan: false,
            active: true,
            permissions: ['get_overrides', 'modify_override'],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeOverrides(gmp, {
      page: 1,
      pageSize: 25,
      sort: 'text',
      filter: '',
      active: '1',
      text: 'control',
      taskName: '',
      taskId: '12345678-1234-1234-1234-123456789abc',
    });

    const override = response.overrides[0];
    expect(response.counts.filtered).toEqual(1);
    expect(override.id).toEqual('9f6c71ce-4f9c-41e2-8c8d-74b8a1aef001');
    expect(override.text).toEqual('Accepted compensating control');
    expect(override.hosts).toEqual(['192.0.2.10']);
    expect(override.port).toEqual('443/tcp');
    expect(override.severity).toEqual(7.5);
    expect(override.newSeverity).toEqual(-1);
    expect(override.nvt?.id).toEqual('1.3.6.1.4.1.25623.1.0.999999');
    expect(override.nvt?.name).toEqual('Example NVT');
    expect(override.isActive()).toEqual(true);
    expect(override.isWritable()).toEqual(true);
    expect(override.userCapabilities.mayEdit('override')).toEqual(true);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/overrides', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'text',
      filter: '',
      active: '1',
      text: 'control',
      task_name: '',
      task_id: '12345678-1234-1234-1234-123456789abc',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/overrides',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('fetches override details with task and result links', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: '9f6c71ce-4f9c-41e2-8c8d-74b8a1aef001',
        owner: {name: 'admin'},
        nvt: {
          id: '1.3.6.1.4.1.25623.1.0.999999',
          name: 'Example NVT',
          type: 'nvt',
        },
        text: 'Accepted compensating control',
        active: false,
        task: {
          id: 'f65533d8-b078-441a-b09b-71a7aeb37091',
          name: 'Weekly scan',
          trash: false,
        },
        result: {
          id: '96fbeff5-793f-4e60-92aa-f1c3e40daf0c',
          name: '96fbeff5-793f-4e60-92aa-f1c3e40daf0c',
        },
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const override = await fetchNativeOverride(
      gmp,
      '9f6c71ce-4f9c-41e2-8c8d-74b8a1aef001',
    );

    expect(override.isActive()).toEqual(false);
    expect(override.task?.id).toEqual('f65533d8-b078-441a-b09b-71a7aeb37091');
    expect(override.task?.name).toEqual('Weekly scan');
    expect(override.result?.id).toEqual('96fbeff5-793f-4e60-92aa-f1c3e40daf0c');
  });

  test('loads the override store through same-origin native API', async () => {
    const filter = Filter.fromString('first=1 rows=10 sort=text active=1');
    const rootState = createState('override', {
      isLoading: {
        [filterIdentifier(filter)]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 10, total: 1, sort: 'text', filter: ''},
        items: [
          {
            id: '9f6c71ce-4f9c-41e2-8c8d-74b8a1aef001',
            owner: {name: 'admin'},
            nvt: {
              id: '1.3.6.1.4.1.25623.1.0.999999',
              name: 'Example NVT',
              type: 'nvt',
            },
            text: 'Accepted compensating control',
            hosts: '192.0.2.10',
            port: '443/tcp',
            severity: 7.5,
            new_severity: -1,
            active: true,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();

    await loadEntities(gmp)(filter)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/overrides', {
      token: 'test-token',
      page: 1,
      page_size: 10,
      sort: 'text',
      filter: '',
      active: '1',
      text: '',
      task_name: '',
    });
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITIES_LOADING_SUCCESS');
    expect(successAction.counts.filtered).toEqual(1);
    expect(successAction.data[0].text).toEqual('Accepted compensating control');
    expect(successAction.data[0].nvt?.name).toEqual('Example NVT');
  });

  test('loads override detail store entries through same-origin native API', async () => {
    const id = '9f6c71ce-4f9c-41e2-8c8d-74b8a1aef001';
    const rootState = createState('override', {
      isLoading: {
        [id]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id,
        text: 'Accepted compensating control',
        active: false,
        task: {
          id: 'f65533d8-b078-441a-b09b-71a7aeb37091',
          name: 'Weekly scan',
          trash: false,
        },
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();

    await loadEntity(gmp)(id)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/overrides/9f6c71ce-4f9c-41e2-8c8d-74b8a1aef001',
      {token: 'test-token'},
    );
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITY_LOADING_SUCCESS');
    expect(successAction.data.text).toEqual('Accepted compensating control');
    expect(successAction.data.task?.name).toEqual('Weekly scan');
  });
});
