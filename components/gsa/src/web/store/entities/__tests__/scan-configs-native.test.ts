/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import ScanConfig from 'gmp/models/scan-config';
import Filter from 'gmp/models/filter';
import {
  fetchNativeScanConfig,
  fetchNativeScanConfigFamilies,
  fetchNativeScanConfigs,
  getNativeScanConfigFamilyNvtChanges,
  patchNativeScanConfigFamilyNvts,
} from 'gmp/native-api/scan-configs';
import {loadEntities, loadEntity} from 'web/store/entities/scanconfigs';
import {createState} from 'web/store/entities/utils/testing';
import {filterIdentifier} from 'web/store/utils';

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

  test('loads the scan-config store list through same-origin native API', async () => {
    const filter = Filter.fromString('first=1 rows=10 sort=name predefined=1');
    const rootState = createState('scanconfig', {
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
    const gmp = createGmp();

    await loadEntities(gmp)(filter)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/scan-configs', {
      token: 'test-token',
      page: 1,
      page_size: 10,
      sort: 'name',
      filter: '',
      predefined: '1',
    });
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITIES_LOADING_SUCCESS');
    expect(successAction.counts.filtered).toEqual(1);
    expect(successAction.data[0]).toBeInstanceOf(ScanConfig);
    expect(successAction.data[0].name).toEqual('Full and fast');
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
        preferences: {
          scanner: [
            {
              name: 'visible-scanner-preference',
              value: 'visible value',
              default: 'scanner default',
              configured: true,
            },
            {
              name: 'redacted-scanner-preference',
              value: 'do-not-expose-scanner-value',
              default: 'do-not-expose-scanner-default',
              configured: true,
              redacted: true,
            },
          ],
          nvt: [
            {
              nvt: {oid: '1.3.6.1.4.1.25623.1.0.1', name: 'Native NVT'},
              id: '42',
              name: 'visible-nvt-preference',
              value: 'enabled;disabled',
              default: 'disabled;enabled;auto',
              type: 'radio',
            },
            {
              nvt: {oid: '1.3.6.1.4.1.25623.1.0.2', name: 'Redacted NVT'},
              id: '43',
              name: 'redacted-nvt-preference',
              value: 'do-not-expose-nvt-value',
              default: 'do-not-expose-nvt-default',
              configured: true,
              redacted: true,
            },
          ],
        },
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
    expect(config.userTags?.[0].id).toEqual(
      '8afbe92e-f808-447c-9399-1492f3f9ef3f',
    );
    expect(config.userTags?.[0].name).toEqual('Native tag');
    expect(config.userTags?.[0].value).toEqual('true');
    expect(config.preferences.scanner[0]).toMatchObject({
      name: 'visible-scanner-preference',
      value: 'visible value',
      default: 'scanner default',
      configured: true,
    });
    expect(config.preferences.scanner[1]).toMatchObject({
      name: 'redacted-scanner-preference',
      configured: true,
      redacted: true,
    });
    expect(config.preferences.scanner[1].value).toBeUndefined();
    expect(config.preferences.scanner[1].default).toBeUndefined();
    expect(config.preferences.nvt[0]).toMatchObject({
      id: '42',
      name: 'visible-nvt-preference',
      nvt: {oid: '1.3.6.1.4.1.25623.1.0.1', name: 'Native NVT'},
      value: 'enabled',
      default: 'disabled',
      alt: ['disabled', 'auto'],
    });
    expect(config.preferences.nvt[1]).toMatchObject({
      id: '43',
      name: 'redacted-nvt-preference',
      configured: true,
      redacted: true,
      nvt: {oid: '1.3.6.1.4.1.25623.1.0.2', name: 'Redacted NVT'},
    });
    expect(JSON.stringify(config)).not.toContain('do-not-expose');
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

  test('computes only changed native scan config family NVT selections', () => {
    expect(
      getNativeScanConfigFamilyNvtChanges(
        [
          {oid: '1.2.3', selected: 1},
          {oid: '1.2.4', selected: 0},
          {oid: '1.2.5', selected: 1},
        ],
        {'1.2.3': 1, '1.2.4': 1, '1.2.5': 0},
      ),
    ).toEqual([
      {oid: '1.2.4', selected: true},
      {oid: '1.2.5', selected: false},
    ]);
  });

  test('patches native scan config family NVT selections without a response body', async () => {
    const fetchMock = testing.fn().mockResolvedValue({ok: true, status: 204});
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    await patchNativeScanConfigFamilyNvts(gmp, 'config/id', 'Port scanners', {
      changes: [{oid: '1.2.3', selected: false}],
    });

    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/scan-configs/config%2Fid/families/Port%20scanners/nvts',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scan-configs/config%2Fid/families/Port%20scanners/nvts',
      {
        method: 'PATCH',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({
          changes: [{oid: '1.2.3', selected: false}],
        }),
      },
    );
  });

  test('loads native detail and families without a GMP detail request', async () => {
    const id = 'daba56c8-73ec-11df-a475-002264764cea';
    const calls: string[] = [];
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
          preferences: {
            scanner: [{name: 'native-scanner-preference', value: 'native'}],
          },
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
        get: testing.fn(),
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
    expect(calls).toHaveLength(2);
    expect(calls).toContain('native-detail');
    expect(calls).toContain('native-families');
    expect(gmp.scanconfig.get).not.toHaveBeenCalled();
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
    expect(config?.preferences.scanner[0].name).toEqual(
      'native-scanner-preference',
    );
    expect(config?.tasks[0].name).toEqual('Native retained task');
    expect(config?.userTags?.[0].name).toEqual('Native retained tag');
    expect(config?.userTags?.[0].value).toEqual('yes');
  });

  test('does not fall back to GMP when a native detail load fails', async () => {
    const id = 'daba56c8-73ec-11df-a475-002264764cea';
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'disabled'}}),
      ok: false,
      status: 503,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      ...createGmp(),
      scanconfig: {get: testing.fn()},
    };
    const dispatch = testing.fn(action => action);
    const getState = () => ({
      entities: {scanconfig: {byId: {}, errors: {}, isLoading: {}}},
    });

    await loadEntity(gmp)(id)(dispatch, getState);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(gmp.scanconfig.get).not.toHaveBeenCalled();
    expect(dispatch.mock.calls[1][0].type).toEqual('ENTITY_LOADING_ERROR');
  });
});
