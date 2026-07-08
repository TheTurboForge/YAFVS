/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {createResponse, createHttp} from 'gmp/commands/testing';
import TrashCanCommand from 'gmp/commands/trashcan';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('TrashCanCommand tests', () => {
  test('should allow to restore an entity', async () => {
    const response = createResponse({});
    const fakeHttp = createHttp(response);
    const cmd = new TrashCanCommand(fakeHttp);
    await cmd.restore({id: '1234'});
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'restore',
        target_id: '1234',
      },
    });
  });

  test('should restore supported trash entities through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: '1234'}),
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
    const cmd = new TrashCanCommand(fakeHttp);

    await cmd.restore({id: '1234', entityType: 'filter'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/filters/1234/restore',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/filters/1234/restore',
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
  });

  test('should fall back to GMP restore for unsupported native trash entities', async () => {
    const response = createResponse({});
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
    const cmd = new TrashCanCommand(fakeHttp);

    await cmd.restore({id: '1234', entityType: 'credential'});

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'restore',
        target_id: '1234',
      },
    });
  });

  test('should not fall back to GMP when supported native restore fails', async () => {
    const response = createResponse({});
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'conflict'}}),
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
    const cmd = new TrashCanCommand(fakeHttp);

    await expect(
      cmd.restore({id: '1234', entityType: 'filter'}),
    ).rejects.toThrow('Native API request failed with status 409');
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should allow to empty the trashcan', async () => {
    const response = createResponse({});
    const fakeHttp = createHttp(response);
    const cmd = new TrashCanCommand(fakeHttp);
    await cmd.empty();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {cmd: 'empty_trashcan'},
    });
  });

  test('should allow to delete an entity from the trashcan', async () => {
    const response = createResponse({});
    const fakeHttp = createHttp(response);
    const cmd = new TrashCanCommand(fakeHttp);
    await cmd.delete({id: '1234', entityType: 'task'});
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'delete_from_trash',
        task_id: '1234',
        resource_type: 'task',
      },
    });
  });

  test('should delete supported trash entities through native API when available', async () => {
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
    const cmd = new TrashCanCommand(fakeHttp);

    await cmd.delete({id: '1234', entityType: 'filter'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/filters/1234/trash');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/filters/1234/trash',
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

  test('should fall back to GMP delete for unsupported native trash entities', async () => {
    const response = createResponse({});
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
    const cmd = new TrashCanCommand(fakeHttp);

    await cmd.delete({id: '1234', entityType: 'task'});

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'delete_from_trash',
        task_id: '1234',
        resource_type: 'task',
      },
    });
  });

  test('should not fall back to GMP when supported native trash delete fails', async () => {
    const response = createResponse({});
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
    const cmd = new TrashCanCommand(fakeHttp);

    await expect(
      cmd.delete({id: '1234', entityType: 'filter'}),
    ).rejects.toThrow('Native API request failed with status 409');
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should allow to delete an host from the trashcan', async () => {
    const response = createResponse({});
    const fakeHttp = createHttp(response);
    const cmd = new TrashCanCommand(fakeHttp);
    await cmd.delete({id: '1234', entityType: 'host'});
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'delete_from_trash',
        asset_id: '1234',
        resource_type: 'asset',
      },
    });
  });

  test('should load trashcan rows through native redacted item API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 500, total: 3},
        items: [
          {
            id: '11111111-1111-1111-1111-111111111111',
            resource_type: 'credentials',
            entity_type: 'credential',
            title: 'Credentials',
            name: 'SSH credential',
            comment: 'redacted row',
          },
          {
            id: '22222222-2222-2222-2222-222222222222',
            resource_type: 'targets',
            entity_type: 'target',
            title: 'Targets',
            name: 'Target without hosts',
          },
          {
            id: '33333333-3333-3333-3333-333333333333',
            resource_type: 'tasks',
            entity_type: 'task',
            title: 'Tasks',
            name: 'Task in trash',
          },
        ],
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
    const cmd = new TrashCanCommand(fakeHttp);

    const data = await cmd.get();

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/trashcan/items', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'resource_type',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/trashcan/items',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(data.data.credentials[0].id).toBe(
      '11111111-1111-1111-1111-111111111111',
    );
    expect(data.data.credentials[0].name).toBe('SSH credential');
    expect(data.data.targets[0].name).toBe('Target without hosts');
    expect(data.data.tasks[0].entityType).toBe('task');
  });

  test('should handle failed requests gracefully', async () => {
    const response = createResponse({
      get_trash: {
        get_alerts_response: {
          alert: [{_id: 'alert1'}],
        },
      },
    });

    const fakeHttp = createHttp(response);
    const cmd = new TrashCanCommand(fakeHttp);
    const data = await cmd.get();

    expect(data.data.alerts.length).toBe(1);
    expect(data.data.scanConfigs.length).toBe(0);

    expect(data.data).toHaveProperty('failedRequests');
  });
});
