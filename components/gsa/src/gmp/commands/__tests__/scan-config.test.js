/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {
  convertPreferences,
  ScanConfigCommand,
  ScanConfigsCommand,
} from 'gmp/commands/scan-configs';
import {
  createEntityResponse,
  createHttp,
  createHttpMany,
  createActionResultResponse,
  createResponse,
} from 'gmp/commands/testing';
import {
  SCANCONFIG_TREND_STATIC,
  SCANCONFIG_TREND_DYNAMIC,
} from 'gmp/models/scan-config';
import {YES_VALUE, NO_VALUE} from 'gmp/parser';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('convertPreferences tests', () => {
  test('should convert preferences', () => {
    const prefenceValues = {
      'foo Password:': {
        id: 1,
        value: undefined,
        type: 'password',
      },
      'foo Username:': {
        id: 2,
        value: 'user',
        type: 'entry',
      },
      bar: {
        id: 3,
        value: 'foo',
        type: 'password',
      },
      foo: {
        id: 4,
        type: 'file',
        value: 'ABC',
      },
    };

    expect(convertPreferences(prefenceValues, '1.2.3')).toEqual({
      'file:1.2.3:4:file:foo': 'yes',
      'password:1.2.3:3:password:bar': 'yes',
      'preference:1.2.3:2:entry:foo Username:': 'user',
      'preference:1.2.3:3:password:bar': 'foo',
      'preference:1.2.3:4:file:foo': 'ABC',
    });
  });

  test('should return empty object if preferences are empty', () => {
    expect(convertPreferences(undefined, '1.2.3')).toEqual({});
    expect(convertPreferences({}, '1.2.3')).toEqual({});
  });
});

describe('ScanConfigsCommand tests', () => {
  test('should fetch scan configs with inherited GMP fallback', async () => {
    const response = createResponse({
      get_configs: {
        get_configs_response: {
          config: [{_id: 'config-1', name: 'Inherited config'}],
        },
      },
    });
    const fakeHttp = createHttp(response);

    const cmd = new ScanConfigsCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25'});

    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_configs',
        filter: 'first=1 rows=25',
        usage_type: 'scan',
      },
    });
    expect(result.data[0].id).toEqual('config-1');
  });

  test('should fetch scan configs through native API when available', async () => {
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
    const fakeHttp = createHttp(undefined);
    fakeHttp.buildUrl = testing.fn(path => `https://turbovas.example/${path}`);
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

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
    const fakeHttp = createHttp(undefined);
    fakeHttp.buildUrl = testing.fn(path => `https://turbovas.example/${path}`);
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

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
});

describe('ScanConfigCommand tests', () => {
  test('should return single config', async () => {
    const response = createEntityResponse('config', {_id: 'foo'});
    const fakeHttp = createHttp(response);
    const cmd = new ScanConfigCommand(fakeHttp);
    const resp = await cmd.get({id: 'foo'});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_config',
        config_id: 'foo',
      },
    });
    const {data} = resp;
    expect(data.id).toEqual('foo');
  });

  test('should import a config', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new ScanConfigCommand(fakeHttp);
    await cmd.import({xml_file: 'content'});
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'import_config',
        xml_file: 'content',
      },
    });
  });

  test('should create a config', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new ScanConfigCommand(fakeHttp);
    await cmd.create({
      baseScanConfig: 'uuid1',
      name: 'foo',
      comment: 'somecomment',
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'create_config',
        base: 'uuid1',
        comment: 'somecomment',
        name: 'foo',
        usage_type: 'scan',
      },
    });
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

  test('should fall back to GMP when native scan config create from base fails', async () => {
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
    await cmd.create({
      baseScanConfig: 'base-scan-config-id',
      name: 'foo',
      comment: 'somecomment',
    });

    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'create_config',
        base: 'base-scan-config-id',
        comment: 'somecomment',
        name: 'foo',
        usage_type: 'scan',
      },
    });
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

  test('should fall back to GMP when native scan config clone fails', async () => {
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
    const result = await cmd.clone({id: 'scan-config-id'});

    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'clone',
        id: 'scan-config-id',
        resource_type: 'config',
      },
    });
    expect(result.data.id).toEqual('fallback-scan-config-clone-id');
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

  test('should save a config', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const trend = {
      'AIX Local Security Checks': SCANCONFIG_TREND_DYNAMIC,
      'Family Foo': SCANCONFIG_TREND_STATIC,
    };
    const select = {
      'AIX Local Security Checks': YES_VALUE,
      'Brute force attacks': YES_VALUE,
      'Foo Family': NO_VALUE,
    };
    const scannerPreferenceValues = {
      foo: 'bar',
    };
    const cmd = new ScanConfigCommand(fakeHttp);
    await cmd.save({
      id: 'c1',
      name: 'foo',
      comment: 'somecomment',
      trend,
      select,
      scannerPreferenceValues,
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_config',
        comment: 'somecomment',
        config_id: 'c1',
        name: 'foo',
        'preference:scanner:scanner:scanner:foo': 'bar',
        'select:AIX Local Security Checks': 1,
        'select:Brute force attacks': 1,
        'trend:AIX Local Security Checks': 1,
        'trend:Family Foo': 0,
      },
    });
  });

  test('should save an in use config with undefined input objects', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new ScanConfigCommand(fakeHttp);
    await cmd.save({
      id: 'c1',
      name: 'foo',
      comment: 'somecomment',
      trend: undefined,
      select: undefined,
      scannerPreferenceValues: undefined,
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_config',
        comment: 'somecomment',
        config_id: 'c1',
        name: 'foo',
      },
    });
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

  test('should save a config family', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const selected = {
      'oid:1': YES_VALUE,
      'oid:2': NO_VALUE,
      'oid:3': YES_VALUE,
    };
    const cmd = new ScanConfigCommand(fakeHttp);
    await cmd.saveScanConfigFamily({
      id: 'c1',
      familyName: 'foo',
      selected,
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_config_family',
        config_id: 'c1',
        family: 'foo',
        'nvt:oid:1': 1,
        'nvt:oid:3': 1,
      },
    });
  });

  test('should save a config nvt', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const preferenceValues = {
      Foo: {
        id: 1,
        value: 'bar',
        type: 'entry',
      },
      Bar: {
        id: 2,
        value: 'foo',
        type: 'password',
      },
    };
    const cmd = new ScanConfigCommand(fakeHttp);
    await cmd.saveScanConfigNvt({
      id: 'c1',
      oid: '1.2.3',
      timeout: 123,
      preferenceValues,
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_config_nvt',
        config_id: 'c1',
        oid: '1.2.3',
        'password:1.2.3:2:password:Bar': 'yes',
        'preference:1.2.3:0:entry:timeout': 123,
        'preference:1.2.3:1:entry:Foo': 'bar',
        'preference:1.2.3:2:password:Bar': 'foo',
        timeout: 1,
      },
    });
  });

  test('should request scan config family data', async () => {
    const response = createResponse({
      get_config_family_response: {
        get_nvts_response: {
          nvt: [
            {
              _oid: 1,
            },
            {
              _oid: 2,
            },
          ],
        },
      },
    });
    const responseAll = createResponse({
      get_config_family_response: {
        get_nvts_response: {
          nvt: [
            {
              _oid: 1,
              cvss_base: 1.1,
            },
            {
              _oid: 2,
              cvss_base: 2.2,
            },
            {
              _oid: 3,
              cvss_base: 3.3,
            },
          ],
        },
      },
    });
    const responses = [response, responseAll];
    const fakeHttp = createHttpMany(responses);
    const cmd = new ScanConfigCommand(fakeHttp);
    const resp = await cmd.editScanConfigFamilySettings({
      id: 'foo',
      familyName: 'bar',
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'edit_config_family',
        config_id: 'foo',
        family: 'bar',
      },
    });
    const {nvts} = resp.data;
    expect(nvts.length).toEqual(3);
    expect(nvts[0].selected).toEqual(YES_VALUE);
    expect(nvts[0].severity).toEqual(1.1);
    expect(nvts[1].selected).toEqual(YES_VALUE);
    expect(nvts[1].severity).toEqual(2.2);
    expect(nvts[2].selected).toEqual(NO_VALUE);
    expect(nvts[2].severity).toEqual(3.3);
  });

  test('should request scan config nvt data', async () => {
    const response = createResponse({
      get_config_nvt_response: {
        get_nvts_response: {
          nvt: {
            _oid: '1.2.3',
          },
        },
      },
    });
    const fakeHttp = createHttp(response);
    const cmd = new ScanConfigCommand(fakeHttp);
    const resp = await cmd.editScanConfigNvtSettings({id: 'foo', oid: '1.2.3'});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_config_nvt',
        config_id: 'foo',
        oid: '1.2.3',
        name: '',
      },
    });
    const {data: nvt} = resp;
    expect(nvt.id).toEqual('1.2.3');
  });
});
