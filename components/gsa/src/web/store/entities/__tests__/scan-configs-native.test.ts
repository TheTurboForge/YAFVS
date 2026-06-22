/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import ScanConfig from 'gmp/models/scan-config';
import {
  fetchNativeScanConfig,
  fetchNativeScanConfigFamilies,
  fetchNativeScanConfigs,
} from 'gmp/native-api/scan-configs';
import {loadEntity} from 'web/store/entities/scanconfigs';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API scan configs', () => {
  test('fetches scan configs as inherited ScanConfig models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: 'daba56c8-73ec-11df-a475-002264764cea',
            name: 'Full and fast',
            comment: 'Default scanner config',
            owner: {name: 'admin'},
            family_count: 33,
            families_growing: 1,
            nvt_count: 177000,
            nvts_growing: 1,
            predefined: true,
            deprecated: false,
            writable: false,
            in_use: true,
            usage_type: 'scan',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeScanConfigs(gmp, {
      page: 1,
      pageSize: 25,
      sort: 'families_total',
      filter: '',
      predefined: '1',
    });

    const config = response.scanConfigs[0];
    expect(response.counts.filtered).toEqual(1);
    expect(config.id).toEqual('daba56c8-73ec-11df-a475-002264764cea');
    expect(config.name).toEqual('Full and fast');
    expect(config.owner?.name).toEqual('admin');
    expect(config.families?.count).toEqual(33);
    expect(config.families?.trend).toEqual(1);
    expect(config.nvts?.count).toEqual(177000);
    expect(config.predefined).toEqual(true);
    expect(config.isWritable()).toEqual(false);
    expect(config.isInUse()).toEqual(true);
    expect(config.tasks).toEqual([]);
    expect(config.userCapabilities.mayEdit('config')).toEqual(true);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/scan-configs', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'families_total',
      filter: '',
      predefined: '1',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scan-configs',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('fetches one scan config from the native detail endpoint', async () => {
    const id = 'daba56c8-73ec-11df-a475-002264764cea';
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id,
        name: 'Full and fast',
        comment: 'Native detail metadata',
        owner: {name: 'admin'},
        family_count: 60,
        families_growing: 1,
        nvt_count: 177769,
        nvts_growing: 1,
        predefined: true,
        deprecated: false,
        writable: false,
        in_use: true,
        tasks: [
          {
            id: 'b14d191b-69a2-43e1-bf03-74d01fcced19',
            name: 'Native task',
            usage_type: 'scan',
          },
        ],
        user_tags: [
          {
            id: '8afbe92e-f808-447c-9399-1492f3f9ef3f',
            name: 'Native tag',
            value: 'true',
            comment: 'Native tag comment',
          },
        ],
        created_at: '2026-06-02T11:57:09Z',
        modified_at: '2026-06-02T11:59:37Z',
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeScanConfig(gmp, id);

    const config = response.scanConfig;
    expect(config.id).toEqual(id);
    expect(config.name).toEqual('Full and fast');
    expect(config.comment).toEqual('Native detail metadata');
    expect(config.families?.count).toEqual(60);
    expect(config.families?.trend).toEqual(1);
    expect(config.nvts?.count).toEqual(177769);
    expect(config.predefined).toEqual(true);
    expect(config.isWritable()).toEqual(false);
    expect(config.isInUse()).toEqual(true);
    expect(config.tasks[0].id).toEqual('b14d191b-69a2-43e1-bf03-74d01fcced19');
    expect(config.tasks[0].name).toEqual('Native task');
    expect(config.userTags?.[0].id).toEqual('8afbe92e-f808-447c-9399-1492f3f9ef3f');
    expect(config.userTags?.[0].name).toEqual('Native tag');
    expect(config.userTags?.[0].value).toEqual('true');
    expect(gmp.buildUrl).toHaveBeenCalledWith(`api/v1/scan-configs/${id}`, {
      token: 'test-token',
    });
  });

  test('fetches scan config NVT families from the native detail endpoint', async () => {
    const id = 'daba56c8-73ec-11df-a475-002264764cea';
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        scan_config_id: id,
        family_count: 2,
        families_growing: 1,
        families: [
          {
            name: 'General',
            nvt_count: 12,
            max_nvt_count: 12,
            growing: 1,
          },
          {
            name: 'Port scanners',
            nvt_count: 3,
            max_nvt_count: 8,
            growing: 0,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeScanConfigFamilies(gmp, id);

    const config = response.scanConfig;
    expect(config.id).toEqual(id);
    expect(config.families?.count).toEqual(2);
    expect(config.families?.trend).toEqual(1);
    expect(config.family_list?.[0].name).toEqual('General');
    expect(config.family_list?.[0].nvts?.count).toEqual(12);
    expect(config.family_list?.[0].nvts?.max).toEqual(12);
    expect(config.family_list?.[0].trend).toEqual(1);
    expect(config.family_list?.[1].name).toEqual('Port scanners');
    expect(config.family_list?.[1].nvts?.count).toEqual(3);
    expect(config.family_list?.[1].nvts?.max).toEqual(8);
    expect(config.family_list?.[1].trend).toEqual(0);
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      `api/v1/scan-configs/${id}/families`,
      {token: 'test-token'},
    );
  });

  test('loads inherited detail context before overlaying native Information fields', async () => {
    const id = 'daba56c8-73ec-11df-a475-002264764cea';
    const calls: string[] = [];
    const inherited = ScanConfig.fromElement({
      _id: id,
      name: 'Inherited config',
      comment: 'inherited comment',
      writable: 1,
      predefined: 0,
      deprecated: 1,
      family_count: {__text: '1', growing: 0},
      nvt_count: {__text: '2', growing: 0},
      families: {
        family: [
          {
            name: 'Inherited family',
            growing: 0,
            nvt_count: '2',
            max_nvt_count: '2',
          },
        ],
      },
      preferences: {
        preference: [
          {
            id: 1,
            name: 'scanner-pref',
            hr_name: 'Scanner preference',
            type: 'entry',
            value: 'retained',
          },
          {
            id: 2,
            name: 'nvt-pref',
            hr_name: 'NVT preference',
            nvt: {_oid: '1.3.6.1.4.1.25623.1.0.1', name: 'Retained NVT'},
            type: 'entry',
            value: 'retained-nvt',
          },
        ],
      },
      scanner: {
        _id: '08b69003-5fc2-4037-a479-93b440211c73',
        __text: 'Inherited Scanner',
      },
      tasks: {
        task: [{_id: 'task-1', name: 'Retained task'}],
      },
      user_tags: {
        tag: [{_id: 'tag-1', name: 'Retained tag', value: 'true'}],
      },
    });
    const fetchMock = testing.fn().mockImplementation((url: string) => {
      if (url.endsWith('/families')) {
        calls.push('native-families');
        return Promise.resolve({
          json: testing.fn().mockResolvedValue({
            scan_config_id: id,
            family_count: 60,
            families_growing: 1,
            families: [
              {
                name: 'Native family',
                nvt_count: 7,
                max_nvt_count: 9,
                growing: 1,
              },
            ],
          }),
          ok: true,
          status: 200,
        });
      }
      calls.push('native-detail');
      return Promise.resolve({
        json: testing.fn().mockResolvedValue({
          id,
          name: 'Native Full and fast',
          comment: 'native comment',
          owner: {name: 'admin'},
          family_count: 60,
          families_growing: 1,
          nvt_count: 177769,
          nvts_growing: 1,
          predefined: true,
          deprecated: false,
          writable: false,
          in_use: true,
          tasks: [
            {
              id: 'native-task-1',
              name: 'Native retained task',
              usage_type: 'scan',
            },
          ],
          user_tags: [
            {
              id: 'native-tag-1',
              name: 'Native retained tag',
              value: 'yes',
              comment: 'native tag comment',
            },
          ],
          created_at: '2026-06-02T11:57:09Z',
          modified_at: '2026-06-02T11:59:37Z',
        }),
        ok: true,
        status: 200,
      });
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      ...createGmp({jwt: 'jwt-token'}),
      scanconfig: {
        get: testing.fn().mockImplementation(() => {
          calls.push('gmp');
          return Promise.resolve({data: inherited});
        }),
      },
    };
    const actions: Array<{type: string; data?: ScanConfig}> = [];
    const dispatch = testing.fn(action => {
      actions.push(action);
      return action;
    });
    const getState = () => ({
      entities: {
        scanconfig: {
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
    const config = success?.data;
    expect(calls).toEqual(['gmp', 'native-detail', 'native-families']);
    expect(gmp.scanconfig.get).toHaveBeenCalledWith({id});
    expect(config).toBeInstanceOf(ScanConfig);
    expect(config?.name).toEqual('Native Full and fast');
    expect(config?.comment).toEqual('native comment');
    expect(config?.families?.count).toEqual(60);
    expect(config?.families?.trend).toEqual(1);
    expect(config?.nvts?.count).toEqual(177769);
    expect(config?.predefined).toEqual(true);
    expect(config?.deprecated).toEqual(false);
    expect(config?.isWritable()).toEqual(false);
    expect(config?.isInUse()).toEqual(true);
    expect(config?.family_list?.[0].name).toEqual('Native family');
    expect(config?.family_list?.[0].nvts?.count).toEqual(7);
    expect(config?.family_list?.[0].nvts?.max).toEqual(9);
    expect(config?.preferences.scanner[0].name).toEqual('scanner-pref');
    expect(config?.preferences.nvt[0].nvt?.oid).toEqual(
      '1.3.6.1.4.1.25623.1.0.1',
    );
    expect(config?.scanner?.name).toEqual('Inherited Scanner');
    expect(config?.tasks[0].name).toEqual('Native retained task');
    expect(config?.userTags?.[0].name).toEqual('Native retained tag');
    expect(config?.userTags?.[0].value).toEqual('yes');
  });
});
