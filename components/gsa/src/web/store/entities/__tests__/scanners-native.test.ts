/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import Credential from 'gmp/models/credential';
import Filter from 'gmp/models/filter';
import Scanner from 'gmp/models/scanner';
import {fetchNativeScanner, fetchNativeScanners} from 'gmp/native-api/scanners';
import {loadEntities, loadEntity} from 'web/store/entities/scanners';
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

describe('native API scanners list', () => {
  test('fetches top-level scanners as inherited Scanner models without credential secrets', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: '08b69003-5fc2-4037-a479-93b440211c73',
            name: 'OpenVAS Default',
            comment: 'scanner metadata only',
            host: '/runtime/run/ospd/ospd-openvas.sock',
            port: 0,
            scanner_type: 2,
            credential: {
              id: '6d799e1f-a81b-4b33-8090-5d4b0ed8ec77',
              name: 'Scanner credential',
            },
            relay_host: '',
            relay_port: 0,
            created_at: '2026-06-18T18:00:00Z',
            modified_at: '2026-06-18T20:00:00Z',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeScanners(gmp, {
      page: 1,
      pageSize: 25,
      sort: 'name',
      filter: '',
    });

    const scanner = response.scanners[0];
    expect(response.counts.filtered).toEqual(1);
    expect(scanner.id).toEqual('08b69003-5fc2-4037-a479-93b440211c73');
    expect(scanner.name).toEqual('OpenVAS Default');
    expect(scanner.comment).toEqual('scanner metadata only');
    expect(scanner.host).toEqual('/runtime/run/ospd/ospd-openvas.sock');
    expect(scanner.hasUnixSocket()).toEqual(true);
    expect(scanner.port).toEqual(0);
    expect(scanner.scannerType).toEqual('2');
    expect(scanner.credential?.id).toEqual(
      '6d799e1f-a81b-4b33-8090-5d4b0ed8ec77',
    );
    expect(scanner.credential?.name).toEqual('Scanner credential');
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/scanners', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/scanners',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('loads scanner list store entries through same-origin native API', async () => {
    const filter = Filter.fromString('first=1 rows=10 sort=name');
    const rootState = createState('scanner', {
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
            id: '08b69003-5fc2-4037-a479-93b440211c73',
            name: 'OpenVAS Default',
            host: '/runtime/run/ospd/ospd-openvas.sock',
            port: 0,
            scanner_type: 2,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      ...createGmp(),
      scanners: {
        get: testing
          .fn()
          .mockRejectedValue(new Error('inherited fallback used')),
      },
    };

    await loadEntities(gmp)(filter)(dispatch, getState);

    expect(gmp.scanners.get).not.toHaveBeenCalled();
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/scanners', {
      token: 'test-token',
      page: 1,
      page_size: 10,
      sort: 'name',
      filter: '',
    });
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITIES_LOADING_SUCCESS');
    expect(successAction.counts.filtered).toEqual(1);
    expect(successAction.data[0]).toBeInstanceOf(Scanner);
    expect(successAction.data[0].name).toEqual('OpenVAS Default');
  });
});

describe('native API scanner detail', () => {
  test('fetches one scanner from the native detail endpoint', async () => {
    const id = '08b69003-5fc2-4037-a479-93b440211c73';
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id,
        name: 'OpenVAS Default',
        comment: 'detail metadata only',
        host: '/runtime/run/ospd/ospd-openvas.sock',
        port: 0,
        scanner_type: 2,
        ca_pub: 'native CA certificate',
        credential: {
          id: '6d799e1f-a81b-4b33-8090-5d4b0ed8ec77',
          name: 'Scanner credential',
        },
        tasks: [
          {
            id: 'task-1',
            name: 'Native task',
            usage_type: 'scan',
          },
        ],
        user_tags: [
          {
            id: 'tag-1',
            name: 'Native tag',
            value: 'true',
            comment: 'active tag',
          },
        ],
        created_at: '2026-06-18T18:00:00Z',
        modified_at: '2026-06-18T20:00:00Z',
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeScanner(gmp, id);

    const scanner = response.scanner;
    expect(scanner.id).toEqual(id);
    expect(scanner.name).toEqual('OpenVAS Default');
    expect(scanner.comment).toEqual('detail metadata only');
    expect(scanner.hasUnixSocket()).toEqual(true);
    expect(scanner.scannerType).toEqual('2');
    expect(scanner.caPub?.certificate).toEqual('native CA certificate');
    expect(scanner.credential?.name).toEqual('Scanner credential');
    expect(scanner.tasks[0].name).toEqual('Native task');
    expect(scanner.userTags[0].name).toEqual('Native tag');
    expect(scanner.credential?.certificateInfo).toBeUndefined();
    expect(gmp.buildUrl).toHaveBeenCalledWith(`api/v1/scanners/${id}`, {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      `https://yafvs.example/api/v1/scanners/${id}`,
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('loads Unix-socket detail without inherited GMP page-load request', async () => {
    const id = '08b69003-5fc2-4037-a479-93b440211c73';
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id,
        name: 'Native Scanner',
        comment: 'native comment',
        host: '/runtime/run/ospd/ospd-openvas.sock',
        port: 0,
        scanner_type: 2,
        credential: {
          id: '6d799e1f-a81b-4b33-8090-5d4b0ed8ec77',
          name: 'Native credential',
        },
        tasks: [
          {
            id: 'task-1',
            name: 'Native task',
            usage_type: 'scan',
          },
        ],
        user_tags: [
          {
            id: 'tag-1',
            name: 'Native tag',
            value: 'true',
            comment: 'active tag',
          },
        ],
        created_at: '2026-06-18T18:00:00Z',
        modified_at: '2026-06-18T20:00:00Z',
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      ...createGmp({jwt: 'jwt-token'}),
      scanner: {
        get: testing.fn(),
      },
    };
    const actions: Array<{type: string; data?: Scanner}> = [];
    const dispatch = testing.fn(action => {
      actions.push(action);
      return action;
    });
    const getState = () => ({
      entities: {
        scanner: {
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
    const scanner = success?.data;
    expect(gmp.scanner.get).not.toHaveBeenCalled();
    expect(scanner).toBeInstanceOf(Scanner);
    expect(scanner?.name).toEqual('Native Scanner');
    expect(scanner?.comment).toEqual('native comment');
    expect(scanner?.host).toEqual('/runtime/run/ospd/ospd-openvas.sock');
    expect(scanner?.port).toEqual(0);
    expect(scanner?.scannerType).toEqual('2');
    expect(scanner?.credential).toBeInstanceOf(Credential);
    expect(scanner?.credential?.name).toEqual('Native credential');
    expect(scanner?.credential?.certificateInfo).toBeUndefined();
    expect(scanner?.caPub).toBeUndefined();
    expect(scanner?.tasks?.[0].name).toEqual('Native task');
    expect(scanner?.userTags?.[0].name).toEqual('Native tag');
    expect(scanner?.isWritable()).toEqual(true);
  });

  test('loads remote scanner detail with one native request and no command fallback', async () => {
    const id = '08b69003-5fc2-4037-a479-93b440211c73';
    const fetchMock = testing.fn().mockImplementation(() => {
      return Promise.resolve({
        json: testing.fn().mockResolvedValue({
          id,
          name: 'Native Scanner',
          comment: 'native comment',
          host: '127.0.0.1',
          port: 443,
          scanner_type: 5,
          ca_pub: 'native CA certificate',
          credential: {
            id: '6d799e1f-a81b-4b33-8090-5d4b0ed8ec77',
            name: 'Native credential',
          },
          tasks: [
            {
              id: 'task-1',
              name: 'Native task',
              usage_type: 'scan',
            },
          ],
          user_tags: [
            {
              id: 'tag-1',
              name: 'Native tag',
              value: 'true',
              comment: '',
            },
          ],
          created_at: '2026-06-18T18:00:00Z',
          modified_at: '2026-06-18T20:00:00Z',
        }),
        ok: true,
        status: 200,
      });
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      ...createGmp({jwt: 'jwt-token'}),
      scanner: {
        get: testing.fn().mockRejectedValue(new Error('fallback used')),
      },
    };
    const actions: Array<{type: string; data?: Scanner}> = [];
    const dispatch = testing.fn(action => {
      actions.push(action);
      return action;
    });
    const getState = () => ({
      entities: {
        scanner: {
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
    const scanner = success?.data;
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(gmp.scanner.get).not.toHaveBeenCalled();
    expect(scanner).toBeInstanceOf(Scanner);
    expect(scanner?.name).toEqual('Native Scanner');
    expect(scanner?.comment).toEqual('native comment');
    expect(scanner?.host).toEqual('127.0.0.1');
    expect(scanner?.port).toEqual(443);
    expect(scanner?.scannerType).toEqual('5');
    expect(scanner?.credential).toBeInstanceOf(Credential);
    expect(scanner?.credential?.name).toEqual('Native credential');
    expect(scanner?.credential?.certificateInfo).toBeUndefined();
    expect(scanner?.caPub?.certificate).toEqual('native CA certificate');
    expect(scanner?.tasks?.[0].name).toEqual('Native task');
    expect(scanner?.configs).toEqual([]);
    expect(scanner?.userTags?.[0].name).toEqual('Native tag');
    expect(scanner?.isWritable()).toEqual(true);
  });
});
