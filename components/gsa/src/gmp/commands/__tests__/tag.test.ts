/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import TagCommand from 'gmp/commands/tag';
import {
  createActionResultResponse,
  createEntityResponse,
  createHttp,
} from 'gmp/commands/testing';
import {NO_VALUE, YES_VALUE} from 'gmp/parser';
import {createSession} from 'gmp/testing';
import {type EntityType} from 'gmp/utils/entity-type';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('TagCommand tests', () => {
  test('should export tag metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'tag-id',
        name: 'Critical assets',
        value: 'critical',
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

    const cmd = new TagCommand(fakeHttp);
    const result = await cmd.export({id: 'tag-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/tags/tag-id/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tags/tag-id/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: 'tag-id',
      name: 'Critical assets',
      value: 'critical',
    });
  });

  test('should create new tag with resources', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new TagCommand(fakeHttp);
    const resp = await cmd.create({
      name: 'name',
      comment: 'comment',
      active: true,
      resourceIds: ['id1', 'id2'],
      resourceType: 'task',
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'create_tag',
        tag_name: 'name',
        comment: 'comment',
        active: YES_VALUE,
        'resource_ids:': ['id1', 'id2'],
        resource_type: 'task',
        tag_value: '',
      },
    });
    const {data} = resp;
    expect(data.id).toEqual('foo');
  });

  test.each([
    {entityType: 'task', resourceType: 'task'},
    {entityType: 'scanconfig', resourceType: 'config'},
    {entityType: 'host', resourceType: 'host'},
    {entityType: 'reportconfig', resourceType: 'report_config'},
    {entityType: 'report', resourceType: 'report'},
    {entityType: 'certbund', resourceType: 'cert_bund_adv'},
    {entityType: 'cve', resourceType: 'cve'},
  ])(
    'should create tag for resource type $entityType',
    async ({entityType, resourceType}) => {
      const response = createActionResultResponse();
      const fakeHttp = createHttp(response);
      const cmd = new TagCommand(fakeHttp);
      const resp = await cmd.create({
        name: 'name',
        comment: 'comment',
        active: true,
        resourceIds: ['id1', 'id2'],
        resourceType: entityType as EntityType,
      });
      expect(fakeHttp.request).toHaveBeenCalledWith('post', {
        data: {
          cmd: 'create_tag',
          tag_name: 'name',
          comment: 'comment',
          active: YES_VALUE,
          'resource_ids:': ['id1', 'id2'],
          resource_type: resourceType,
          tag_value: '',
        },
      });
      const {data} = resp;
      expect(data.id).toEqual('foo');
    },
  );

  test('should create new tag with filter', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new TagCommand(fakeHttp);
    const resp = await cmd.create({
      name: 'name',
      comment: 'comment',
      active: true,
      filter: 'some filter',
      resourceType: 'task',
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'create_tag',
        tag_name: 'name',
        comment: 'comment',
        active: YES_VALUE,
        filter: 'some filter',
        resource_type: 'task',
        tag_value: '',
      },
    });
    const {data} = resp;
    expect(data.id).toEqual('foo');
  });

  test('should create a metadata-only tag through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-tag-id'}),
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

    const cmd = new TagCommand(fakeHttp);
    const result = await cmd.create({
      active: false,
      comment: 'comment',
      name: 'name',
      resourceType: 'task',
      value: 'value',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/tags');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tags',
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
          active: false,
          comment: 'comment',
          name: 'name',
          resource_type: 'task',
          value: 'value',
        }),
      },
    );
    expect(result.data.id).toEqual('native-tag-id');
  });

  test('should create a selected-resource tag through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-tag-id'}),
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

    const cmd = new TagCommand(fakeHttp);
    const result = await cmd.create({
      active: true,
      comment: 'comment',
      name: 'name',
      resourceIds: ['target-id-1', 'target-id-2'],
      resourceType: 'target',
      value: 'value',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tags',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          active: true,
          comment: 'comment',
          name: 'name',
          resource_ids: ['target-id-1', 'target-id-2'],
          resource_type: 'target',
          value: 'value',
        }),
      }),
    );
    expect(result.data.id).toEqual('native-tag-id');
  });

  test('should not fall back to GMP when native metadata-only tag create fails', async () => {
    const response = createActionResultResponse({id: 'fallback-tag-id'});
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

    const cmd = new TagCommand(fakeHttp);

    await expect(
      cmd.create({
        active: true,
        comment: 'comment',
        name: 'name',
        resourceType: 'task',
      }),
    ).rejects.toThrow('Native API request failed with status 503');
    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject native tag create with filter instead of falling back to GMP', async () => {
    const response = createActionResultResponse({id: 'fallback-tag-id'});
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

    const cmd = new TagCommand(fakeHttp);

    await expect(
      cmd.create({
        active: true,
        filter: 'some filter',
        name: 'name',
        resourceType: 'task',
      }),
    ).rejects.toThrow('Native tag create with filters is not supported');
    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should not fall back to GMP when native selected-resource tag create fails', async () => {
    const response = createActionResultResponse({id: 'fallback-tag-id'});
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'forbidden'}}),
      ok: false,
      status: 403,
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

    const cmd = new TagCommand(fakeHttp);

    await expect(
      cmd.create({
        active: true,
        name: 'name',
        resourceIds: ['target-id-1'],
        resourceType: 'target',
      }),
    ).rejects.toThrow('Native API request failed with status 403');
    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject native tag save with filter instead of falling back to GMP', async () => {
    const response = createActionResultResponse({id: 'fallback-tag-id'});
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

    const cmd = new TagCommand(fakeHttp);

    await expect(
      cmd.save({
        id: 'tag-id',
        name: 'bar',
        active: true,
        filter: 'some filter',
        resourceIds: ['id1'],
        resourceType: 'task',
        resourcesAction: 'add',
      }),
    ).rejects.toThrow('Native tag save with filters is not supported');
    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject ambiguous native tag resource save instead of falling back to GMP', async () => {
    const response = createActionResultResponse({id: 'fallback-tag-id'});
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

    const cmd = new TagCommand(fakeHttp);

    await expect(
      cmd.save({
        id: 'tag-id',
        name: 'bar',
        active: true,
        resourceIds: ['id1'],
        resourceType: 'task',
      }),
    ).rejects.toThrow(
      'Native tag resource updates require explicit add, remove, or set action',
    );
    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should return single tag', async () => {
    const response = createEntityResponse('tag', {_id: 'foo'});
    const fakeHttp = createHttp(response);
    const cmd = new TagCommand(fakeHttp);
    const resp = await cmd.get({id: 'foo'});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_tag',
        tag_id: 'foo',
      },
    });
    const {data} = resp;
    expect(data.id).toEqual('foo');
  });

  test('should return single tag through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'tag-id',
        name: 'Critical assets',
        value: 'critical',
        resource_type: 'host',
        active: true,
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

    const cmd = new TagCommand(fakeHttp);
    const resp = await cmd.get({id: 'tag-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/tags/tag-id', {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tags/tag-id',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(resp.data.id).toEqual('tag-id');
    expect(resp.data.name).toEqual('Critical assets');
  });

  test('should return single tag resources filter through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'foo',
        name: 'Critical assets',
        resources: {type: 'task', count: {total: 2}},
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

    const cmd = new TagCommand(fakeHttp);
    const resp = await cmd.get({id: 'foo'}, {filter: 'resources=1'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/tags/foo', {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalled();
    expect(resp.data.id).toEqual('foo');
    expect(resp.data.resourceType).toEqual('task');
    expect(resp.data.resourceCount).toEqual(2);
  });

  test('should return single tag alerts filter through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'foo',
        name: 'Critical assets',
        resources: {type: 'task', count: {total: 2}},
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

    const cmd = new TagCommand(fakeHttp);
    const resp = await cmd.get({id: 'foo'}, {filter: 'alerts=1'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/tags/foo', {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalled();
    expect(resp.data.id).toEqual('foo');
    expect(resp.data.resourceType).toEqual('task');
    expect(resp.data.resourceCount).toEqual(2);
  });

  test('should reject unsupported native tag detail filters', async () => {
    const fetchMock = testing.fn();
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
    const cmd = new TagCommand(fakeHttp);

    await expect(cmd.get({id: 'foo'}, {filter: 'results=1'})).rejects.toThrow(
      'Native tag detail filter is not supported',
    );

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should save a tag', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new TagCommand(fakeHttp);
    await cmd.save({
      id: 'foo',
      name: 'bar',
      comment: 'ipsum',
      active: true,
      resourceIds: ['id1'],
      resourceType: 'task',
      resourcesAction: 'add',
      value: 'lorem',
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_tag',
        tag_id: 'foo',
        tag_name: 'bar',
        comment: 'ipsum',
        active: YES_VALUE,
        'resource_ids:': ['id1'],
        resource_type: 'task',
        resources_action: 'add',
        tag_value: 'lorem',
      },
    });
  });

  test('should save tag metadata through native API when no resources or filter are supplied', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-tag-id'}),
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

    const cmd = new TagCommand(fakeHttp);
    const result = await cmd.save({
      id: 'tag-id',
      name: 'bar',
      comment: 'ipsum',
      active: false,
      resourceType: 'task',
      value: 'lorem',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/tags/tag-id');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tags/tag-id',
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
          active: false,
          comment: 'ipsum',
          name: 'bar',
          value: 'lorem',
        }),
      },
    );
    expect(result.data.id).toEqual('native-tag-id');
  });

  test('should update explicit tag resources through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-tag-id'}),
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

    const cmd = new TagCommand(fakeHttp);
    const result = await cmd.save({
      id: 'tag-id',
      name: 'bar',
      active: true,
      resourceIds: ['id1', 'id2'],
      resourceType: 'task',
      resourcesAction: 'add',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/tags/tag-id/resources',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tags/tag-id/resources',
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
          action: 'add',
          resource_ids: ['id1', 'id2'],
        }),
      },
    );
    expect(result.data.id).toEqual('native-tag-id');
  });

  test.each(['add', 'remove', 'set'] as const)(
    'should not fall back to GMP when native tag resource %s fails',
    async resourcesAction => {
      const response = createActionResultResponse({id: 'fallback-tag-id'});
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

      const cmd = new TagCommand(fakeHttp);

      await expect(
        cmd.save({
          id: 'tag-id',
          name: 'bar',
          active: true,
          resourceIds: ['id1'],
          resourceType: 'task',
          resourcesAction,
        }),
      ).rejects.toThrow('Native API request failed with status 409');
      expect(fetchMock).toHaveBeenCalled();
      expect(fakeHttp.request).not.toHaveBeenCalled();
    },
  );

  test('should update tag resources through native API for set', async () => {
    const response = createActionResultResponse({id: 'fallback-tag-id'});
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-tag-id'}),
      ok: true,
      status: 200,
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
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new TagCommand(fakeHttp);
    const result = await cmd.save({
      id: 'tag-id',
      name: 'bar',
      active: true,
      resourceIds: ['id1', 'id2'],
      resourceType: 'task',
      resourcesAction: 'set',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/tags/tag-id/resources',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tags/tag-id/resources',
      expect.objectContaining({
        body: JSON.stringify({
          action: 'set',
          resource_ids: ['id1', 'id2'],
        }),
        method: 'POST',
      }),
    );
    expect(result.data.id).toEqual('native-tag-id');
  });

  test('should not fall back to GMP when native tag save fails', async () => {
    const response = createActionResultResponse({id: 'fallback-tag-id'});
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

    const cmd = new TagCommand(fakeHttp);

    await expect(
      cmd.save({
        id: 'tag-id',
        name: 'bar',
        active: true,
        resourceType: 'task',
      }),
    ).rejects.toThrow('Native API request failed with status 409');
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should save a tag with filter', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new TagCommand(fakeHttp);
    await cmd.save({
      id: 'foo',
      name: 'bar',
      comment: 'ipsum',
      active: true,
      filter: 'some filter',
      resourceIds: ['id1'],
      resourceType: 'task',
      resourcesAction: 'add',
      value: 'lorem',
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_tag',
        tag_id: 'foo',
        tag_name: 'bar',
        comment: 'ipsum',
        active: YES_VALUE,
        filter: 'some filter',
        'resource_ids:': ['id1'],
        resource_type: 'task',
        resources_action: 'add',
        tag_value: 'lorem',
      },
    });
  });

  test.each([
    {entityType: 'task', resourceType: 'task'},
    {entityType: 'scanconfig', resourceType: 'config'},
    {entityType: 'host', resourceType: 'host'},
    {entityType: 'reportconfig', resourceType: 'report_config'},
    {entityType: 'report', resourceType: 'report'},
    {entityType: 'certbund', resourceType: 'cert_bund_adv'},
    {entityType: 'cve', resourceType: 'cve'},
  ])(
    'should save tag for resource type $entityType',
    async ({entityType, resourceType}) => {
      const response = createActionResultResponse();
      const fakeHttp = createHttp(response);
      const cmd = new TagCommand(fakeHttp);
      await cmd.save({
        id: 'foo',
        active: true,
        name: 'bar',
        resourceType: entityType as EntityType,
      });
      expect(fakeHttp.request).toHaveBeenCalledWith('post', {
        data: {
          cmd: 'save_tag',
          comment: '',
          tag_id: 'foo',
          tag_name: 'bar',
          active: YES_VALUE,
          resource_type: resourceType,
          tag_value: '',
        },
      });
    },
  );

  test('should enable a tag', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new TagCommand(fakeHttp);
    await cmd.enable({
      id: 'foo',
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'toggle_tag',
        tag_id: 'foo',
        enable: YES_VALUE,
      },
    });
  });

  test('should enable a tag through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-tag-id'}),
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

    const cmd = new TagCommand(fakeHttp);
    const result = await cmd.enable({id: 'tag-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/tags/tag-id');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tags/tag-id',
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
          active: true,
        }),
      },
    );
    expect(result.data.id).toEqual('native-tag-id');
  });

  test('should disable a tag', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new TagCommand(fakeHttp);
    await cmd.disable({
      id: 'foo',
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'toggle_tag',
        tag_id: 'foo',
        enable: NO_VALUE,
      },
    });
  });

  test('should disable a tag through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-tag-id'}),
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

    const cmd = new TagCommand(fakeHttp);
    const result = await cmd.disable({id: 'tag-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/tags/tag-id');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tags/tag-id',
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
          active: false,
        }),
      },
    );
    expect(result.data.id).toEqual('native-tag-id');
  });

  test('should clone a tag through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-clone-id'}),
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

    const cmd = new TagCommand(fakeHttp);
    const result = await cmd.clone({id: 'tag-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/tags/tag-id/clone');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tags/tag-id/clone',
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
    expect(result.data.id).toEqual('native-clone-id');
  });

  test('should not fall back to GMP when native tag clone fails', async () => {
    const response = createActionResultResponse({
      action: 'Clone Tag',
      id: 'fallback-clone-id',
      message: 'Cloned Tag',
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

    const cmd = new TagCommand(fakeHttp);

    await expect(cmd.clone({id: 'tag-id'})).rejects.toThrow(
      'Native API request failed with status 503',
    );
    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should delete a tag through native API when available', async () => {
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

    const cmd = new TagCommand(fakeHttp);
    await cmd.delete({id: 'tag-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/tags/tag-id');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tags/tag-id',
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

  test('should not fall back to GMP when native tag delete fails', async () => {
    const response = createActionResultResponse({id: 'fallback-tag-id'});
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

    const cmd = new TagCommand(fakeHttp);

    await expect(cmd.delete({id: 'tag-id'})).rejects.toThrow(
      'Native API request failed with status 409',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });
});
