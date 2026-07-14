/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {
  ScanConfigCommand,
  ScanConfigsCommand,
} from 'gmp/commands/scan-configs';
import {
  createHttp,
  createActionResultResponse,
} from 'gmp/commands/testing';
import Filter from 'gmp/models/filter';
import {
  SCANCONFIG_TREND_STATIC,
  SCANCONFIG_TREND_DYNAMIC,
} from 'gmp/models/scan-config';
import {YES_VALUE, NO_VALUE} from 'gmp/parser';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

const createNativeHttp = () => {
  const fakeHttp = createHttp(undefined);
  fakeHttp.buildUrl = testing.fn(path => `https://turbovas.example/${path}`);
  fakeHttp.session = createSession();
  fakeHttp.session.token = 'test-token';
  fakeHttp.session.jwt = 'jwt-token';
  return fakeHttp;
};

describe('ScanConfigsCommand tests', () => {
  test('should fetch scan configs through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: 'base'},
        items: [
          {
            id: 'd21f6c81-2b88-4ac1-b7b4-a2a9f2ad4663',
            name: 'Base',
            comment: 'Basic configuration template',
            family_count: 2,
            nvt_count: 3,
            predefined: true,
            writable: false,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new ScanConfigsCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=base'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('d21f6c81-2b88-4ac1-b7b4-a2a9f2ad4663');
    expect(result.data[0].name).toEqual('Base');
    expect(result.data[0].predefined).toEqual(true);
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/scan-configs', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: 'base',
      predefined: '',
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

  test('should page through native API for getAll', async () => {
    const responses = [
      {
        page: {page: 1, page_size: 2, total: 3, sort: 'name', filter: ''},
        items: [
          {id: 'config-1', name: 'One'},
          {id: 'config-2', name: 'Two'},
        ],
      },
      {
        page: {page: 2, page_size: 2, total: 3, sort: 'name', filter: ''},
        items: [{id: 'config-3', name: 'Three'}],
      },
    ];
    const fetchMock = testing.fn().mockImplementation(() =>
      Promise.resolve({
        json: testing.fn().mockResolvedValue(responses.shift()),
        ok: true,
        status: 200,
      }),
    );
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new ScanConfigsCommand(fakeHttp);
    const result = await cmd.getAll();

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data).toHaveLength(3);
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/scan-configs',
      {
        token: 'test-token',
        page: 1,
        page_size: 500,
        sort: 'name',
        filter: '',
        predefined: '',
      },
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/scan-configs',
      {
        token: 'test-token',
        page: 2,
        page_size: 500,
        sort: 'name',
        filter: '',
        predefined: '',
      },
    );
  });

  test('should bulk export selected scan configs through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'config-1', name: 'One'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'config-2', name: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScanConfigsCommand(fakeHttp);

    const result = await cmd.exportByIds(['config-1', 'config-2']);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/scan-configs/config-1/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).scan_configs).toEqual([
      {id: 'config-1', name: 'One'},
      {id: 'config-2', name: 'Two'},
    ]);
  });

  test('should bulk export current page filter through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 2,
            page_size: 1,
            total: 3,
            sort: 'name',
            filter: 'base',
          },
          items: [{id: 'config-2', name: 'Two'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'config-2', name: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScanConfigsCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=base');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/scan-configs',
      {
        token: 'test-token',
        page: 2,
        page_size: 1,
        sort: 'name',
        filter: 'base',
        predefined: '',
      },
    );
    expect(JSON.parse(result.data).scan_configs).toEqual([
      {id: 'config-2', name: 'Two'},
    ]);
  });

  test('should bulk export all filtered scan configs through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'name',
            filter: 'base',
          },
          items: [{id: 'config-1', name: 'One'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 2,
            page_size: 500,
            total: 2,
            sort: 'name',
            filter: 'base',
          },
          items: [{id: 'config-2', name: 'Two'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'config-1', name: 'One'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'config-2', name: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScanConfigsCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=base').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/scan-configs',
      {
        token: 'test-token',
        page: 1,
        page_size: 500,
        sort: 'name',
        filter: 'base',
        predefined: '',
      },
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/scan-configs',
      {
        token: 'test-token',
        page: 2,
        page_size: 500,
        sort: 'name',
        filter: 'base',
        predefined: '',
      },
    );
    expect(JSON.parse(result.data).scan_configs).toEqual([
      {id: 'config-1', name: 'One'},
      {id: 'config-2', name: 'Two'},
    ]);
  });
});

describe('ScanConfigCommand tests', () => {
  test('should return a native detail and families without GMP fallback', async () => {
    const id = 'daba56c8-73ec-11df-a475-002264764cea';
    const fetchMock = testing.fn().mockImplementation(url =>
      Promise.resolve({
        json: testing.fn().mockResolvedValue(
          url.endsWith('/families')
            ? {
                scan_config_id: id,
                families: [
                  {
                    name: 'Port scanners',
                    nvt_count: 1,
                    max_nvt_count: 2,
                  },
                ],
              }
            : {
                id,
                name: 'Native config',
                preferences: {
                  scanner: [{name: 'native-preference', value: 'native'}],
                },
              },
        ),
        ok: true,
        status: 200,
      }),
    );
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScanConfigCommand(fakeHttp);

    const response = await cmd.get({id});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      `api/v1/scan-configs/${id}`,
      {token: 'test-token'},
    );
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      `api/v1/scan-configs/${id}/families`,
      {token: 'test-token'},
    );
    expect(response.data.family_list[0].name).toEqual('Port scanners');
    expect(response.data.preferences.scanner[0].value).toEqual('native');
  });

  test('should not fall back to GMP when a native detail request fails', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'disabled'}}),
      ok: false,
      status: 503,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScanConfigCommand(fakeHttp);

    await expect(cmd.get({id: 'scan-config-id'})).rejects.toThrow(
      'Native API request failed with status 503',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should import a scan config JSON backup through native API', async () => {
    const backup = {
      schema: 'turbovas.scan-config-backup',
      version: 1,
      usage_type: 'scan',
      name: 'Imported config',
    };
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'imported-config-id'}),
      ok: true,
      status: 201,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScanConfigCommand(fakeHttp);
    const result = await cmd.import({jsonFile: JSON.stringify(backup)});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/scan-configs/import',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scan-configs/import',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify(backup),
      },
    );
    expect(result.data.id).toEqual('imported-config-id');
  });

  test('should reject invalid scan config backup JSON before any request', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScanConfigCommand(fakeHttp);

    await expect(cmd.import({jsonFile: 'not json'})).rejects.toThrow(
      'Scan config backup must contain valid JSON.',
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('should download a scan config JSON backup through native API', async () => {
    const backup = new ArrayBuffer(8);
    const fetchMock = testing.fn().mockResolvedValue({
      arrayBuffer: testing.fn().mockResolvedValue(backup),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined);
    fakeHttp.buildUrl = testing.fn(path => `https://turbovas.example/${path}`);
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new ScanConfigCommand(fakeHttp);
    const result = await cmd.export({id: 'scan-config-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/scan-configs/scan-config-id/backup',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scan-configs/scan-config-id/backup',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data).toBe(backup);
  });

  test('should create a scan config from base through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-scan-config-id'}),
      ok: true,
      status: 201,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined);
    fakeHttp.buildUrl = testing.fn(path => `https://turbovas.example/${path}`);
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new ScanConfigCommand(fakeHttp);
    const result = await cmd.create({
      baseScanConfig: 'base-scan-config-id',
      name: 'foo',
      comment: 'somecomment',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/scan-configs');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scan-configs',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({
          base_scan_config_id: 'base-scan-config-id',
          comment: 'somecomment',
          name: 'foo',
        }),
      },
    );
    expect(result.data.id).toEqual('native-scan-config-id');
  });

  test('should not fall back to GMP when native scan config create from base fails', async () => {
    const response = createActionResultResponse();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'disabled'}}),
      ok: false,
      status: 503,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response);
    fakeHttp.buildUrl = testing.fn(path => `https://turbovas.example/${path}`);
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new ScanConfigCommand(fakeHttp);

    await expect(
      cmd.create({
        baseScanConfig: 'base-scan-config-id',
        name: 'foo',
        comment: 'somecomment',
      }),
    ).rejects.toThrow('Native API request failed with status 503');
    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should clone a scan config through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-scan-config-clone-id'}),
      ok: true,
      status: 201,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined);
    fakeHttp.buildUrl = testing.fn(path => `https://turbovas.example/${path}`);
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new ScanConfigCommand(fakeHttp);
    const result = await cmd.clone({id: 'scan-config-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/scan-configs/scan-config-id/clone',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scan-configs/scan-config-id/clone',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({}),
      },
    );
    expect(result.data.id).toEqual('native-scan-config-clone-id');
  });

  test('should not fall back to GMP when native scan config clone fails', async () => {
    const response = createActionResultResponse({
      action: 'Clone Scan Config',
      id: 'fallback-scan-config-clone-id',
      message: 'Cloned Scan Config',
    });
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'disabled'}}),
      ok: false,
      status: 503,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response);
    fakeHttp.buildUrl = testing.fn(path => `https://turbovas.example/${path}`);
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new ScanConfigCommand(fakeHttp);

    await expect(cmd.clone({id: 'scan-config-id'})).rejects.toThrow(
      'Native API request failed with status 503',
    );
    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should delete a scan config through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: true,
      status: 204,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined);
    fakeHttp.buildUrl = testing.fn(path => `https://turbovas.example/${path}`);
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new ScanConfigCommand(fakeHttp);
    await cmd.delete({id: 'scan-config-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/scan-configs/scan-config-id',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scan-configs/scan-config-id',
      {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('should not fall back to GMP when native scan config delete fails', async () => {
    const response = createActionResultResponse({
      id: 'fallback-scan-config-id',
    });
    const fetchMock = testing.fn().mockResolvedValue({
      ok: false,
      status: 409,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response);
    fakeHttp.buildUrl = testing.fn(path => `https://turbovas.example/${path}`);
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new ScanConfigCommand(fakeHttp);

    await expect(cmd.delete({id: 'scan-config-id'})).rejects.toThrow(
      'Native API request failed with status 409',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should save metadata through the native API when only name and comment are provided', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'scan-config-id'}),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined);
    fakeHttp.buildUrl = testing.fn(path => `https://turbovas.example/${path}`);
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new ScanConfigCommand(fakeHttp);
    const result = await cmd.save({
      id: 'scan-config-id',
      name: 'Native name',
      comment: 'Native comment',
      trend: undefined,
      select: undefined,
      scannerPreferenceValues: undefined,
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/scan-configs/scan-config-id',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scan-configs/scan-config-id',
      {
        method: 'PATCH',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({comment: 'Native comment', name: 'Native name'}),
      },
    );
    expect(result.data.id).toEqual('scan-config-id');
  });

  test('should reject unsupported native scan config save payloads without GMP fallback', async () => {
    const response = createActionResultResponse({
      id: 'fallback-scan-config-id',
    });
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response);
    fakeHttp.buildUrl = testing.fn(path => `https://turbovas.example/${path}`);
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new ScanConfigCommand(fakeHttp);

    expect(() =>
      cmd.save({
        id: 'scan-config-id',
        name: 'Native name',
        comment: 'Native comment',
        select: {General: YES_VALUE},
      }),
    ).toThrow(
      'Native scan config family selection requires both trend and select maps',
    );

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should save complete family selection through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'scan-config-id'}),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScanConfigCommand(fakeHttp);

    await cmd.save({
      id: 'scan-config-id',
      name: 'Native name',
      comment: 'Native comment',
      familyTrend: SCANCONFIG_TREND_DYNAMIC,
      trend: {
        'Zulu family': SCANCONFIG_TREND_STATIC,
        'Alpha family': SCANCONFIG_TREND_DYNAMIC,
      },
      select: {
        'Zulu family': NO_VALUE,
        'Alpha family': YES_VALUE,
      },
      scannerPreferenceValues: {
        'Max checks': 10,
      },
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scan-configs/scan-config-id',
      expect.objectContaining({
        method: 'PATCH',
        body: JSON.stringify({
          comment: 'Native comment',
          family_selection: {
            families_growing: true,
            families: [
              {growing: true, name: 'Alpha family', selected: true},
              {growing: false, name: 'Zulu family', selected: false},
            ],
          },
          name: 'Native name',
          preferences: [
            {
              scope: 'scanner',
              name: 'Max checks',
              action: 'set',
              value: '10',
            },
          ],
        }),
      }),
    );
  });

  test('should order native family selection by the sorted union of map keys', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'scan-config-id'}),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScanConfigCommand(fakeHttp);

    await cmd.save({
      id: 'scan-config-id',
      name: 'Native name',
      familyTrend: SCANCONFIG_TREND_STATIC,
      trend: {
        Beta: SCANCONFIG_TREND_STATIC,
        Alpha: SCANCONFIG_TREND_DYNAMIC,
        Gamma: SCANCONFIG_TREND_STATIC,
      },
      select: {Gamma: YES_VALUE, Alpha: NO_VALUE, Beta: YES_VALUE},
    });

    const {body} = fetchMock.mock.calls[0][1];
    expect(JSON.parse(body).family_selection.families).toEqual([
      {growing: true, name: 'Alpha', selected: false},
      {growing: false, name: 'Beta', selected: true},
      {growing: false, name: 'Gamma', selected: true},
    ]);
  });

  test('should reject empty or inconsistent native family maps locally', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScanConfigCommand(fakeHttp);

    expect(() =>
      cmd.save({
        id: 'scan-config-id',
        name: 'Native name',
        familyTrend: SCANCONFIG_TREND_STATIC,
        trend: {},
        select: {},
      }),
    ).toThrow(
      'Native scan config family selection maps must contain at least one family',
    );

    expect(() =>
      cmd.save({
        id: 'scan-config-id',
        name: 'Native name',
        familyTrend: SCANCONFIG_TREND_STATIC,
        trend: {Alpha: SCANCONFIG_TREND_STATIC},
        select: {Beta: YES_VALUE},
      }),
    ).toThrow(
      'Native scan config family selection maps must contain every family in both maps',
    );

    expect(() =>
      cmd.save({
        id: 'scan-config-id',
        name: 'Native name',
        trend: {Alpha: SCANCONFIG_TREND_STATIC},
        select: {Alpha: YES_VALUE},
      }),
    ).toThrow(
      'Native scan config family selection requires an explicit family trend',
    );

    expect(() =>
      cmd.save({
        id: 'scan-config-id',
        name: 'Native name',
        familyTrend: SCANCONFIG_TREND_STATIC,
        trend: {Alpha: 99},
        select: {Alpha: YES_VALUE},
      }),
    ).toThrow(
      'Native scan config family trends must be explicitly static or dynamic',
    );

    expect(() =>
      cmd.save({
        id: 'scan-config-id',
        name: 'Native name',
        familyTrend: SCANCONFIG_TREND_STATIC,
        trend: {Alpha: SCANCONFIG_TREND_STATIC},
        select: {Alpha: 'maybe'},
      }),
    ).toThrow(
      'Native scan config family selections must be explicitly yes or no',
    );

    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('should save native scanner preference values without GMP fallback', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'scan-config-id'}),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScanConfigCommand(fakeHttp);

    await cmd.save({
      id: 'scan-config-id',
      name: 'Native name',
      comment: 'Native comment',
      scannerPreferenceValues: {foo: 'bar', omitted: undefined},
    });

    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scan-configs/scan-config-id',
      expect.objectContaining({
        method: 'PATCH',
        body: JSON.stringify({
          comment: 'Native comment',
          name: 'Native name',
          preferences: [
            {scope: 'scanner', name: 'foo', action: 'set', value: 'bar'},
          ],
        }),
      }),
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should save NVT entry, radio, password, and file preferences through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'scan-config-id'}),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScanConfigCommand(fakeHttp);

    await cmd.saveScanConfigNvt({
      id: 'scan-config-id',
      oid: '1.2.3',
      timeout: 123,
      preferenceValues: {
        Entry: {id: 1, type: 'entry', value: 'entry value'},
        Radio: {id: 2, type: 'radio', value: 2},
        Password: {id: 3, type: 'password', value: 'password value'},
        File: {id: 4, type: 'file', value: 'file value'},
      },
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scan-configs/scan-config-id',
      expect.objectContaining({
        method: 'PATCH',
        body: JSON.stringify({
          preferences: [
            {
              scope: 'nvt',
              name: 'Entry',
              action: 'set',
              value: 'entry value',
              nvt: {oid: '1.2.3', id: 1, type: 'entry'},
            },
            {
              scope: 'nvt',
              name: 'Radio',
              action: 'set',
              value: '2',
              nvt: {oid: '1.2.3', id: 2, type: 'radio'},
            },
            {
              scope: 'nvt',
              name: 'Password',
              action: 'set',
              value: 'password value',
              nvt: {oid: '1.2.3', id: 3, type: 'password'},
            },
            {
              scope: 'nvt',
              name: 'File',
              action: 'set',
              value: 'file value',
              nvt: {oid: '1.2.3', id: 4, type: 'file'},
            },
            {
              scope: 'nvt',
              name: 'timeout',
              action: 'set',
              value: '123',
              nvt: {oid: '1.2.3', id: 0, type: 'entry'},
            },
          ],
        }),
      }),
    );
  });

  test('should omit undefined native password and file preferences', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'scan-config-id'}),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScanConfigCommand(fakeHttp);

    await cmd.saveScanConfigNvt({
      id: 'scan-config-id',
      oid: '1.2.3',
      timeout: 30,
      preferenceValues: {
        Password: {id: 1, type: 'password', value: undefined},
        File: {id: 2, type: 'file', value: undefined},
      },
    });

    const {body} = fetchMock.mock.calls[0][1];
    expect(JSON.parse(body).preferences).toEqual([
      {
        scope: 'nvt',
        name: 'timeout',
        action: 'set',
        value: '30',
        nvt: {oid: '1.2.3', id: 0, type: 'entry'},
      },
    ]);
  });

  test('should reset an undefined native NVT timeout', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'scan-config-id'}),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScanConfigCommand(fakeHttp);

    await cmd.saveScanConfigNvt({
      id: 'scan-config-id',
      oid: '1.2.3',
      timeout: undefined,
      preferenceValues: {},
    });

    const {body} = fetchMock.mock.calls[0][1];
    expect(JSON.parse(body).preferences).toEqual([
      {
        scope: 'nvt',
        name: 'timeout',
        action: 'reset',
        nvt: {oid: '1.2.3', id: 0, type: 'entry'},
      },
    ]);
  });

  test('should request native scan config family NVT data', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        scan_config_id: 'scan-config-id',
        family: 'Port scanners',
        items: [
          {oid: '1.2.3', name: 'First NVT', severity: 7.5, selected: true},
          {oid: '1.2.4', name: 'Second NVT', severity: 2.1, selected: false},
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScanConfigCommand(fakeHttp);

    const response = await cmd.editScanConfigFamilySettings({
      id: 'scan-config-id',
      familyName: 'Port scanners',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/scan-configs/scan-config-id/families/Port%20scanners/nvts',
      {token: 'test-token'},
    );
    expect(response.data).toEqual({
      nvts: [
        {oid: '1.2.3', name: 'First NVT', severity: 7.5, selected: YES_VALUE},
        {oid: '1.2.4', name: 'Second NVT', severity: 2.1, selected: NO_VALUE},
      ],
    });
  });

  test('should save only changed scan config family NVTs through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({ok: true, status: 204});
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScanConfigCommand(fakeHttp);

    await cmd.saveScanConfigFamily({
      id: 'scan-config-id',
      familyName: 'Port scanners',
      nvts: [
        {oid: '1.2.3', selected: YES_VALUE},
        {oid: '1.2.4', selected: NO_VALUE},
      ],
      selected: {'1.2.3': YES_VALUE, '1.2.4': YES_VALUE},
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/scan-configs/scan-config-id/families/Port%20scanners/nvts',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scan-configs/scan-config-id/families/Port%20scanners/nvts',
      expect.objectContaining({
        method: 'PATCH',
        body: JSON.stringify({
          changes: [{oid: '1.2.4', selected: true}],
        }),
      }),
    );
  });

  test('should skip an unchanged native scan config family save', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScanConfigCommand(fakeHttp);

    await cmd.saveScanConfigFamily({
      id: 'scan-config-id',
      familyName: 'Port scanners',
      nvts: [{oid: '1.2.3', selected: YES_VALUE}],
      selected: {'1.2.3': YES_VALUE},
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('should reject an oversized native scan config family save atomically', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScanConfigCommand(fakeHttp);
    const nvts = Array.from({length: 1025}, (_, index) => ({
      oid: `1.2.${index}`,
      selected: NO_VALUE,
    }));
    const selected = Object.fromEntries(nvts.map(({oid}) => [oid, YES_VALUE]));

    await expect(
      cmd.saveScanConfigFamily({
        id: 'scan-config-id',
        familyName: 'Port scanners',
        nvts,
        selected,
      }),
    ).rejects.toThrow(
      'A single scan config family save may change at most 1024 NVTs',
    );
    expect(fakeHttp.buildUrl).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

});
