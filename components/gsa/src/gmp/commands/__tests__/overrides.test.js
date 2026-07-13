/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {OverrideCommand, OverridesCommand} from 'gmp/commands/overrides';
import {createHttp, createResponse} from 'gmp/commands/testing';
import Filter from 'gmp/models/filter';
import Override from 'gmp/models/override';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

const createNativeHttp = response => {
  const fakeHttp = createHttp(response);
  fakeHttp.buildUrl = testing.fn(path => `https://turbovas.example/${path}`);
  fakeHttp.session = createSession();
  fakeHttp.session.token = 'test-token';
  fakeHttp.session.jwt = 'jwt-token';
  return fakeHttp;
};

const nativeJsonResponse = (payload, status = 200) => ({
  json: testing.fn().mockResolvedValue(payload),
  ok: true,
  status,
});

describe('OverridesCommand tests', () => {
  test('should fetch override detail through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'override-id',
        owner: {name: 'admin'},
        nvt: {id: '1.3.6.1.4.1.25623.1.0.999999', name: 'Example NVT'},
        text: 'Accepted compensating control',
        hosts: '192.0.2.10',
        port: '443/tcp',
        severity: 7.5,
        new_severity: -1,
        active: true,
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new OverrideCommand(fakeHttp);
    const result = await cmd.get({id: 'override-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/overrides/override-id',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/overrides/override-id',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data.id).toEqual('override-id');
    expect(result.data.text).toEqual('Accepted compensating control');
    expect(result.data.hosts).toEqual(['192.0.2.10']);
    expect(result.data.newSeverity).toEqual(-1);
  });

  test('should fetch filtered override detail through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue(
      nativeJsonResponse({
        id: 'override-id',
        text: 'Accepted compensating control',
        result: {id: 'result-id', name: 'Result 1'},
      }),
    );
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new OverrideCommand(fakeHttp);
    const result = await cmd.get({id: 'override-id'}, {filter: 'results=1'});

    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/overrides/override-id',
      {token: 'test-token'},
    );
    expect(result.data.id).toEqual('override-id');
    expect(result.data.result.id).toEqual('result-id');
  });

  test('should create an override through native API with translated fields', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValue(nativeJsonResponse({id: 'created-override-id'}, 201));
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new OverrideCommand(fakeHttp);
    const result = await cmd.create({
      oid: 'nvt-oid',
      text: 'Accepted compensating control',
      active: '1',
      days: 14,
      hosts: '1',
      hosts_manual: '192.0.2.10',
      port: '1',
      port_manual: '443/tcp',
      severity: 7.5,
      custom_severity: 1,
      newSeverity: 6.5,
      task_id: '0',
      task_uuid: 'task-id',
      result_id: '0',
      result_uuid: 'result-id',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/overrides',
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
          nvt_id: 'nvt-oid',
          text: 'Accepted compensating control',
          hosts: '192.0.2.10',
          port: '443/tcp',
          severity: 7.5,
          new_severity: 6.5,
          task_id: 'task-id',
          result_id: 'result-id',
          activation: {mode: 'for_days', days: 14},
        }),
      },
    );
    expect(result.data.id).toEqual('created-override-id');
  });

  test('should patch an override partially and preserve activation for until-active edits', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValue(nativeJsonResponse({id: 'override-id'}));
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new OverrideCommand(fakeHttp);
    const result = await cmd.save({
      id: 'override-id',
      text: 'Updated text',
      active: '-2',
      hosts: '0',
      custom_severity: 0,
      new_severity_from_list: -1,
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/overrides/override-id',
      expect.objectContaining({
        method: 'PATCH',
        body: JSON.stringify({
          text: 'Updated text',
          hosts: null,
          new_severity: -1,
        }),
      }),
    );
    expect(result.data.id).toEqual('override-id');
  });

  test('should clone an override through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValue(nativeJsonResponse({id: 'cloned-override-id'}, 201));
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new OverrideCommand(fakeHttp);
    const result = await cmd.clone({id: 'override/id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/overrides/override%2Fid/clone',
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
    expect(result.data.id).toEqual('cloned-override-id');
  });

  test.each(['create', 'save', 'clone'])(
    'should not fall back to GMP when native override %s fails',
    async operation => {
      const fetchMock = testing.fn().mockResolvedValue({
        ok: false,
        status: 500,
      });
      testing.stubGlobal('fetch', fetchMock);
      const response = createResponse({
        action_result: {id: 'fallback-id', action: operation, message: 'OK'},
      });
      const fakeHttp = createNativeHttp(response);
      const cmd = new OverrideCommand(fakeHttp);

      const promise = {
        create: () =>
          cmd.create({oid: 'nvt-oid', text: 'text', new_severity: -1}),
        save: () => cmd.save({id: 'override-id', text: 'text'}),
        clone: () => cmd.clone({id: 'override-id'}),
      }[operation]();

      await expect(promise).rejects.toThrow(
        'Native API request failed with status 500',
      );
      expect(fakeHttp.request).not.toHaveBeenCalled();
    },
  );

  test('should export override metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'override-id',
        text: 'Accepted compensating control',
        hosts: '192.0.2.10',
        port: '443/tcp',
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new OverrideCommand(fakeHttp);
    const result = await cmd.export({id: 'override-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/overrides/override-id/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/overrides/override-id/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: 'override-id',
      text: 'Accepted compensating control',
      hosts: '192.0.2.10',
      port: '443/tcp',
    });
  });

  test('should move override to trash through native API without GMP fallback', async () => {
    const fetchMock = testing.fn().mockResolvedValue({ok: true, status: 204});
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new OverrideCommand(fakeHttp);
    await cmd.delete({id: 'override-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/overrides/override-id',
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

  test('should not fall back to GMP when native override deletion fails', async () => {
    const fetchMock = testing.fn().mockResolvedValue({ok: false, status: 500});
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new OverrideCommand(fakeHttp);

    await expect(cmd.delete({id: 'override-id'})).rejects.toThrow(
      'Native API request failed with status 500',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should fetch overrides through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 25,
          total: 1,
          sort: 'text',
          filter: 'control',
        },
        items: [
          {
            id: '9f6c71ce-4f9c-41e2-8c8d-74b8a1aef001',
            owner: {name: 'admin'},
            nvt: {
              id: '1.3.6.1.4.1.25623.1.0.999999',
              name: 'Example NVT',
            },
            text: 'Accepted compensating control',
            hosts: '192.0.2.10',
            port: '443/tcp',
            severity: 7.5,
            new_severity: -1,
            active: true,
            permissions: ['get_overrides', 'modify_override'],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new OverridesCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=control'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('9f6c71ce-4f9c-41e2-8c8d-74b8a1aef001');
    expect(result.data[0].text).toEqual('Accepted compensating control');
    expect(result.data[0].hosts).toEqual(['192.0.2.10']);
    expect(result.data[0].newSeverity).toEqual(-1);
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/overrides', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'text',
      filter: 'control',
      active: '',
      text: '',
      task_name: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/overrides',
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
        page: {page: 1, page_size: 2, total: 3, sort: 'text', filter: ''},
        items: [
          {id: 'override-1', nvt: {id: 'nvt-1', name: 'NVT 1'}, text: 'One'},
          {id: 'override-2', nvt: {id: 'nvt-2', name: 'NVT 2'}, text: 'Two'},
        ],
      },
      {
        page: {page: 2, page_size: 2, total: 3, sort: 'text', filter: ''},
        items: [
          {id: 'override-3', nvt: {id: 'nvt-3', name: 'NVT 3'}, text: 'Three'},
        ],
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

    const cmd = new OverridesCommand(fakeHttp);
    const result = await cmd.getAll();

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data).toHaveLength(3);
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/overrides', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'text',
      filter: '',
      active: '',
      text: '',
      task_name: '',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/overrides', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'text',
      filter: '',
      active: '',
      text: '',
      task_name: '',
    });
  });

  test('should bulk export selected overrides through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'override-1', text: 'One'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'override-2', text: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new OverridesCommand(fakeHttp);

    const result = await cmd.export([
      new Override({id: 'override-1'}),
      new Override({id: 'override-2'}),
    ]);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/overrides/override-1/export',
      {token: 'test-token'},
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/overrides/override-2/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).overrides).toEqual([
      {id: 'override-1', text: 'One'},
      {id: 'override-2', text: 'Two'},
    ]);
  });

  test('should move selected overrides to trash through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({ok: true, status: 204});
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new OverridesCommand(fakeHttp);
    const overrides = [
      new Override({id: 'override-1'}),
      new Override({id: 'override-2'}),
    ];

    const result = await cmd.delete(overrides);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data).toEqual(overrides);
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'https://turbovas.example/api/v1/overrides/override-1',
      expect.objectContaining({method: 'DELETE'}),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'https://turbovas.example/api/v1/overrides/override-2',
      expect.objectContaining({method: 'DELETE'}),
    );
  });

  test('should bulk export current page overrides through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 2,
            page_size: 1,
            total: 3,
            sort: 'text',
            filter: 'control',
          },
          items: [{id: 'override-2', text: 'Two'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'override-2', text: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new OverridesCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=control');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/overrides', {
      token: 'test-token',
      page: 2,
      page_size: 1,
      sort: 'text',
      filter: 'control',
      active: '',
      text: '',
      task_name: '',
    });
    expect(JSON.parse(result.data).overrides).toEqual([
      {id: 'override-2', text: 'Two'},
    ]);
  });

  test('should bulk export all filtered overrides through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'text',
            filter: 'control',
          },
          items: [{id: 'override-1', text: 'One'}],
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
            sort: 'text',
            filter: 'control',
          },
          items: [{id: 'override-2', text: 'Two'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'override-1', text: 'One'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'override-2', text: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new OverridesCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=control').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/overrides', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'text',
      filter: 'control',
      active: '',
      text: '',
      task_name: '',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/overrides', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'text',
      filter: 'control',
      active: '',
      text: '',
      task_name: '',
    });
    expect(JSON.parse(result.data).overrides).toEqual([
      {id: 'override-1', text: 'One'},
      {id: 'override-2', text: 'Two'},
    ]);
  });
});
