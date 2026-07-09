/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {FilterCommand} from 'gmp/commands/filter';
import {
  createHttp,
  createActionResultResponse,
  createResponse,
} from 'gmp/commands/testing';
import {createSession} from 'gmp/testing';
import type {EntityType} from 'gmp/utils/entity-type';

afterEach(() => {
  testing.unstubAllGlobals();
});

interface FilterResourceMapping {
  entityType: EntityType;
  resourceType: string;
}

describe('FilterCommand tests', () => {
  test('should fetch filter detail through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'filter-id',
        name: 'Host filter',
        comment: 'Native metadata',
        filter_type: 'host',
        term: 'name=web',
        alert_count: 0,
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

    const cmd = new FilterCommand(fakeHttp);
    const result = await cmd.get({id: 'filter-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/filters/filter-id',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/filters/filter-id',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data.id).toEqual('filter-id');
    expect(result.data.name).toEqual('Host filter');
  });

  test('should fetch filter alert detail through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'filter-id',
        name: 'Host filter',
        term: 'name=web',
        alert_count: 1,
        alerts: [{id: 'alert-id', name: 'Notify SecOps'}],
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

    const cmd = new FilterCommand(fakeHttp);
    const result = await cmd.get({id: 'filter-id'}, {filter: 'alerts=1'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/filters/filter-id',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/filters/filter-id',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data.id).toEqual('filter-id');
    expect(result.data.alerts[0].id).toEqual('alert-id');
  });

  test('should fetch harmless filtered filter detail through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'filter-id',
        name: 'Host filter',
        term: 'name=web',
        type: 'host',
        alert_count: 0,
        alerts: [],
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

    const cmd = new FilterCommand(fakeHttp);
    const result = await cmd.get({id: 'filter-id'}, {filter: 'rows=1'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/filters/filter-id',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data.id).toEqual('filter-id');
  });

  test('should export filter metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'filter-id',
        name: 'Host filter',
        term: 'name=web',
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

    const cmd = new FilterCommand(fakeHttp);
    const result = await cmd.export({id: 'filter-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/filters/filter-id/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/filters/filter-id/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: 'filter-id',
      name: 'Host filter',
      term: 'name=web',
    });
  });

  test('should require native API support for filter create', async () => {
    const fakeHttp = createHttp(createActionResultResponse({id: 'fallback-id'}));
    const cmd = new FilterCommand(fakeHttp);

    await expect(
      cmd.create({
        name: 'Test Filter 1',
        type: 'host',
        term: 'name=Test',
      }),
    ).rejects.toThrow('Native filter API is required for filter command');
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should create a new filter through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-filter-id'}),
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

    const cmd = new FilterCommand(fakeHttp);
    const result = await cmd.create({
      name: 'Test Filter 1',
      type: 'host',
      term: 'name=Test',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/filters');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/filters',
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
          name: 'Test Filter 1',
          comment: '',
          filter_type: 'host',
          term: 'name=Test',
        }),
      },
    );
    expect(result.data.id).toEqual('native-filter-id');
  });

  test('should not fall back to GMP when native filter create fails', async () => {
    const response = createActionResultResponse({
      action: 'create_filter',
      id: '123',
      message: 'Filter created successfully',
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

    const cmd = new FilterCommand(fakeHttp);

    await expect(
      cmd.create({
        name: 'Test Filter 1',
        type: 'host',
        term: 'name=Test',
      }),
    ).rejects.toThrow('Native API request failed with status 503');
    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject unsupported native filter create payloads', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(createActionResultResponse({id: 'fallback-id'})) as ReturnType<
      typeof createHttp
    > & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new FilterCommand(fakeHttp);

    await expect(
      cmd.create({
        name: 'Test Filter 1',
        type: undefined as unknown as EntityType,
        term: 'name=Test',
      }),
    ).rejects.toThrow('Native filter create received unsupported resource type');
    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should clone a filter through native API when available', async () => {
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

    const cmd = new FilterCommand(fakeHttp);
    const result = await cmd.clone({id: 'filter-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/filters/filter-id/clone',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/filters/filter-id/clone',
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

  test('should not fall back to GMP when native filter clone fails', async () => {
    const response = createActionResultResponse({
      action: 'Clone Filter',
      id: '456',
      message: 'Cloned Filter with id 123',
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

    const cmd = new FilterCommand(fakeHttp);

    await expect(cmd.clone({id: '123'})).rejects.toThrow(
      'Native API request failed with status 503',
    );
    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should delete a filter through native API when available', async () => {
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

    const cmd = new FilterCommand(fakeHttp);
    await cmd.delete({id: 'filter-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/filters/filter-id');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/filters/filter-id',
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

  test('should not fall back to GMP when native filter delete fails', async () => {
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

    const cmd = new FilterCommand(fakeHttp);

    await expect(cmd.delete({id: 'filter-id'})).rejects.toThrow(
      'Native API request failed with status 409',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should require native API support for filter save', async () => {
    const fakeHttp = createHttp(createActionResultResponse({id: 'fallback-id'}));
    const cmd = new FilterCommand(fakeHttp);

    await expect(
      cmd.save({
        id: '123',
        name: 'Test Filter 1',
        type: 'host',
        term: 'name=Test',
      }),
    ).rejects.toThrow('Native filter API is required for filter command');
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should save an existing filter through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-filter-id'}),
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

    const cmd = new FilterCommand(fakeHttp);
    const result = await cmd.save({
      id: 'filter-id',
      name: 'Test Filter 1',
      type: 'host',
      term: 'name=Test',
      comment: 'comment',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/filters/filter-id');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/filters/filter-id',
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
          name: 'Test Filter 1',
          comment: 'comment',
          filter_type: 'host',
          term: 'name=Test',
        }),
      },
    );
    expect(result.data.id).toEqual('native-filter-id');
  });

  test('should not fall back to GMP when native filter save fails', async () => {
    const response = createActionResultResponse({id: 'fallback-id'});
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'alert in use'}}),
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

    const cmd = new FilterCommand(fakeHttp);

    await expect(
      cmd.save({
        id: 'filter-id',
        name: 'Test Filter 1',
        type: 'host',
        term: 'name=Test',
      }),
    ).rejects.toThrow('Native API request failed with status 409');
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject unsupported native filter save payloads', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(createActionResultResponse({id: 'fallback-id'})) as ReturnType<
      typeof createHttp
    > & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new FilterCommand(fakeHttp);

    await expect(
      cmd.save({
        id: 'filter-id',
        name: 'Test Filter 1',
        type: undefined as unknown as EntityType,
        term: 'name=Test',
      }),
    ).rejects.toThrow('Native filter save received unsupported resource type');
    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test.each<FilterResourceMapping>([
    {entityType: 'host', resourceType: 'host'},
    {entityType: 'operatingsystem', resourceType: 'os'},
    {entityType: 'report', resourceType: 'report'},
    {entityType: 'result', resourceType: 'result'},
    {entityType: 'task', resourceType: 'task'},
  ])(
    'should create $entityType filter with native $resourceType resource type',
    async ({entityType, resourceType}) => {
      const fetchMock = testing.fn().mockResolvedValue({
        json: testing.fn().mockResolvedValue({id: 'native-filter-id'}),
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

      const cmd = new FilterCommand(fakeHttp);
      const result = await cmd.create({
        name: 'Test Filter',
        term: 'name=Test',
        type: entityType,
      });
      expect(fakeHttp.request).not.toHaveBeenCalled();
      expect(fetchMock).toHaveBeenCalledWith(
        'https://turbovas.example/api/v1/filters',
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
            name: 'Test Filter',
            comment: '',
            filter_type: resourceType,
            term: 'name=Test',
          }),
        },
      );
      expect(result.data.id).toEqual('native-filter-id');
    },
  );
});
