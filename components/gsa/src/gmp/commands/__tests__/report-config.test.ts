/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {ReportConfigCommand} from 'gmp/commands/report-config';
import {
  createHttp,
  createEntityResponse,
  createActionResultResponse,
  createPlainResponse,
} from 'gmp/commands/testing';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('ReportConfigCommand tests', () => {
  test('should return single report config', async () => {
    const response = createEntityResponse('report_config', {
      _id: 'foo',
    });

    const fakeHttp = createHttp(response);
    const cmd = new ReportConfigCommand(fakeHttp);
    const resp = await cmd.get({id: 'foo'});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_report_config',
        report_config_id: 'foo',
      },
    });
    const {data} = resp;
    expect(data.id).toEqual('foo');
  });

  test('should export report config metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'report-config-id',
        name: 'Report config',
        report_format: {id: 'report-format-id', name: 'PDF'},
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new ReportConfigCommand(fakeHttp);
    const result = await cmd.export({id: 'report-config-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/report-configs/report-config-id/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/report-configs/report-config-id/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: 'report-config-id',
      name: 'Report config',
      report_format: {id: 'report-format-id', name: 'PDF'},
    });
  });

  test('should fall back to GMP when native report config metadata export fails', async () => {
    const content = '<some><xml>exported-data</xml></some>';
    const response = createPlainResponse(content);
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'disabled'}}),
      ok: false,
      status: 503,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new ReportConfigCommand(fakeHttp);
    const result = await cmd.export({id: 'report-config-id'});

    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'bulk_export',
        resource_type: 'report_config',
        bulk_select: 1,
        'bulk_selected:report-config-id': 1,
      },
    });
    expect(result.data).toEqual(content);
  });

  test('should create report config', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new ReportConfigCommand(fakeHttp);
    const resp = await cmd.create({
      name: 'foo',
      comment: 'bar',
      reportFormatId: 'baz',
      params: {
        'param 1': 'value 1',
        'param 2': 'value 2',
        'param 3': ['report-format-1', 'report-format-2'],
        'param 4': ['option-1', 'option-2'],
      },
      paramsUsingDefault: {
        'param 1': false,
        'param 2': true,
        'param 3': false,
        'param 4': false,
      },
      paramTypes: {
        'param 1': 'string',
        'param 2': 'text',
        'param 3': 'report_format_list',
        'param 4': 'multi_selection',
      },
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'create_report_config',
        name: 'foo',
        comment: 'bar',
        report_format_id: 'baz',
        'param:param 1': 'value 1',
        'param:param 2': 'value 2',
        'param:param 3': 'report-format-1,report-format-2',
        'param:param 4': '["option-1","option-2"]',
        'param_using_default:param 2': 1,
      },
    });
    const {data} = resp;
    expect(data.id).toEqual('foo');
  });

  test('should create report config through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-report-config-id'}),
      ok: true,
      status: 201,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new ReportConfigCommand(fakeHttp);
    const resp = await cmd.create({
      name: 'native config',
      comment: 'native comment',
      reportFormatId: 'report-format-id',
      params: {
        body: ['a', 'b'],
        formats: ['report-format-1', 'report-format-2'],
        timezone: 'UTC',
      },
      paramsUsingDefault: {
        timezone: true,
      },
      paramTypes: {
        body: 'multi_selection',
        formats: 'report_format_list',
        timezone: 'string',
      },
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/report-configs');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/report-configs',
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
          name: 'native config',
          report_format_id: 'report-format-id',
          comment: 'native comment',
          params: [
            {name: 'body', value: '["a","b"]'},
            {name: 'formats', value: 'report-format-1,report-format-2'},
          ],
        }),
      },
    );
    expect(resp.data.id).toEqual('native-report-config-id');
  });

  test('should not fall back to GMP when native report config create fails', async () => {
    const response = createActionResultResponse({id: 'fallback-id'});
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'duplicate'}}),
      ok: false,
      status: 409,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new ReportConfigCommand(fakeHttp);

    await expect(
      cmd.create({
        name: 'native config',
        reportFormatId: 'report-format-id',
      }),
    ).rejects.toThrow('Native API request failed with status 409');
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should save report config', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new ReportConfigCommand(fakeHttp);
    const resp = await cmd.save({
      id: 'foo',
      name: 'foo',
      comment: 'bar',
      params: {
        'param 1': 'value A',
        'param 2': 'value B',
        'param 3': ['report-format-A', 'report-format-B'],
        'param 4': ['option-1', 'option-2'],
      },
      paramsUsingDefault: {
        'param 1': true,
        'param 2': false,
        'param 3': false,
        'param 4': false,
      },
      paramTypes: {
        'param 1': 'string',
        'param 2': 'text',
        'param 3': 'report_format_list',
        'param 4': 'multi_selection',
      },
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_report_config',
        report_config_id: 'foo',
        name: 'foo',
        comment: 'bar',
        'param:param 1': 'value A',
        'param:param 2': 'value B',
        'param:param 3': 'report-format-A,report-format-B',
        'param:param 4': '["option-1","option-2"]',
        'param_using_default:param 1': 1,
      },
    });
    const {data} = resp;
    expect(data.id).toEqual('foo');
  });

  test('should save report config through native API when no defaults are toggled', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-report-config-id'}),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new ReportConfigCommand(fakeHttp);
    const resp = await cmd.save({
      id: 'report-config-id',
      name: 'native config',
      comment: 'native comment',
      params: {
        body: ['a', 'b'],
        formats: ['report-format-1', 'report-format-2'],
      },
      paramsUsingDefault: {
        body: false,
        formats: false,
      },
      paramTypes: {
        body: 'multi_selection',
        formats: 'report_format_list',
      },
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/report-configs/report-config-id',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/report-configs/report-config-id',
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
          name: 'native config',
          comment: 'native comment',
          params: [
            {name: 'body', value: '["a","b"]'},
            {name: 'formats', value: 'report-format-1,report-format-2'},
          ],
        }),
      },
    );
    expect(resp.data.id).toEqual('native-report-config-id');
  });

  test('should save report config defaults through native API with complete param state', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-report-config-id'}),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new ReportConfigCommand(fakeHttp);
    const resp = await cmd.save({
      id: 'report-config-id',
      name: 'native config',
      params: {subject: 'Daily', timezone: 'UTC'},
      paramsUsingDefault: {subject: false, timezone: true},
      paramTypes: {subject: 'string', timezone: 'string'},
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/report-configs/report-config-id',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/report-configs/report-config-id',
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
          name: 'native config',
          params: [{name: 'subject', value: 'Daily'}],
        }),
      },
    );
    expect(resp.data.id).toEqual('native-report-config-id');
  });

  test('should send empty native params when all report config params use defaults', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-report-config-id'}),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new ReportConfigCommand(fakeHttp);
    await cmd.save({
      id: 'report-config-id',
      name: 'native config',
      params: {timezone: 'UTC'},
      paramsUsingDefault: {timezone: true},
      paramTypes: {timezone: 'string'},
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/report-configs/report-config-id',
      expect.objectContaining({
        method: 'PATCH',
        body: JSON.stringify({
          name: 'native config',
          params: [],
        }),
      }),
    );
  });

  test('should keep report config save on GMP when default state is incomplete', async () => {
    const response = createActionResultResponse({id: 'foo'});
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new ReportConfigCommand(fakeHttp);
    const resp = await cmd.save({
      id: 'foo',
      name: 'foo',
      params: {timezone: 'UTC'},
      paramsUsingDefault: {subject: false, timezone: true},
      paramTypes: {timezone: 'string'},
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_report_config',
        report_config_id: 'foo',
        name: 'foo',
        comment: undefined,
        'param:timezone': 'UTC',
        'param_using_default:timezone': 1,
      },
    });
    expect(resp.data.id).toEqual('foo');
  });

  test('should omit params from native report config save when params are not supplied', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-report-config-id'}),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new ReportConfigCommand(fakeHttp);
    await cmd.save({
      id: 'report-config-id',
      name: 'native config',
      comment: 'native comment',
    });

    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/report-configs/report-config-id',
      expect.objectContaining({
        method: 'PATCH',
        body: JSON.stringify({
          name: 'native config',
          comment: 'native comment',
        }),
      }),
    );
  });

  test('should not fall back to GMP when native report config save fails', async () => {
    const response = createActionResultResponse({id: 'fallback-id'});
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'duplicate'}}),
      ok: false,
      status: 409,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new ReportConfigCommand(fakeHttp);

    await expect(
      cmd.save({
        id: 'report-config-id',
        name: 'native config',
        paramsUsingDefault: {},
      }),
    ).rejects.toThrow('Native API request failed with status 409');
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should delete report config', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new ReportConfigCommand(fakeHttp);
    await cmd.delete({
      id: 'foo',
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'delete_report_config',
        report_config_id: 'foo',
      },
    });
  });

  test('should delete report config through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: true,
      status: 204,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new ReportConfigCommand(fakeHttp);
    await cmd.delete({id: 'report-config-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/report-configs/report-config-id',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/report-configs/report-config-id',
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

  test('should not fall back to GMP when native report config delete fails', async () => {
    const response = createActionResultResponse({id: 'fallback-id'});
    const fetchMock = testing.fn().mockResolvedValue({
      ok: false,
      status: 409,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new ReportConfigCommand(fakeHttp);

    await expect(cmd.delete({id: 'report-config-id'})).rejects.toThrow(
      'Native API request failed with status 409',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should clone a report config through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing
        .fn()
        .mockResolvedValue({id: 'native-report-config-clone-id'}),
      ok: true,
      status: 201,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new ReportConfigCommand(fakeHttp);
    const result = await cmd.clone({id: 'report-config-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/report-configs/report-config-id/clone',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/report-configs/report-config-id/clone',
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
    expect(result.data.id).toEqual('native-report-config-clone-id');
  });

  test('should fall back to GMP when native report config clone fails', async () => {
    const response = createActionResultResponse({
      action: 'Clone Report Config',
      id: 'fallback-report-config-clone-id',
      message: 'Cloned Report Config',
    });
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'disabled'}}),
      ok: false,
      status: 503,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new ReportConfigCommand(fakeHttp);
    const result = await cmd.clone({id: 'report-config-id'});

    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'clone',
        id: 'report-config-id',
        resource_type: 'report_config',
      },
    });
    expect(result.data.id).toEqual('fallback-report-config-clone-id');
  });
});
