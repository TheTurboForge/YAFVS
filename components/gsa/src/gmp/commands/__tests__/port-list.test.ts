/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {FROM_FILE, PortListCommand} from 'gmp/commands/port-lists';
import {
  createHttp,
  createActionResultResponse,
  createHttpMany,
  createEntityResponse,
  createPlainResponse,
} from 'gmp/commands/testing';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('PortListCommand', () => {
  test('should export port list metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'port-list-id',
        name: 'Web ports',
        port_ranges: [{protocol: 'tcp', start: 80, end: 443}],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const http = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    http.buildUrl = testing.fn(path => `https://turbovas.example/${path}`);
    http.session = createSession();
    http.session.token = 'test-token';
    http.session.jwt = 'jwt-token';

    const command = new PortListCommand(http);
    const result = await command.export({id: 'port-list-id'});

    expect(http.request).not.toHaveBeenCalled();
    expect(http.buildUrl).toHaveBeenCalledWith(
      'api/v1/port-lists/port-list-id/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/port-lists/port-list-id/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: 'port-list-id',
      name: 'Web ports',
      port_ranges: [{protocol: 'tcp', start: 80, end: 443}],
    });
  });

  test('should fall back to GMP when native port list metadata export fails', async () => {
    const content = '<some><xml>exported-data</xml></some>';
    const response = createPlainResponse(content);
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'disabled'}}),
      ok: false,
      status: 503,
    });
    testing.stubGlobal('fetch', fetchMock);
    const http = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    http.buildUrl = testing.fn(path => `https://turbovas.example/${path}`);
    http.session = createSession();
    http.session.token = 'test-token';

    const command = new PortListCommand(http);
    const result = await command.export({id: 'port-list-id'});

    expect(fetchMock).toHaveBeenCalled();
    expect(http.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'bulk_export',
        resource_type: 'port_list',
        bulk_select: 1,
        'bulk_selected:port-list-id': 1,
      },
    });
    expect(result.data).toEqual(content);
  });

  test('should allow to create a port list', async () => {
    const response = createActionResultResponse({
      id: '12345',
    });

    const http = createHttp(response);
    const command = new PortListCommand(http);

    const params = {
      name: 'Test Port List',
      comment: 'This is a test port list',
      portRange: 'tcp:1-1000',
    };

    const result = await command.create(params);

    expect(result.data).toEqual({
      id: '12345',
    });
  });

  test('should allow to create port list from file', async () => {
    const response = createActionResultResponse({
      id: '12345',
    });
    const http = createHttp(response);
    const command = new PortListCommand(http);
    const result = await command.create({
      name: 'Test Port List',
      comment: 'This is a test port list',
      fromFile: FROM_FILE,
      file: new File(['some file content'], 'portlist.txt'),
    });
    expect(result.data).toEqual({
      id: '12345',
    });
  });

  test('should create a typed port list through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-port-list-id'}),
      ok: true,
      status: 201,
    });
    testing.stubGlobal('fetch', fetchMock);
    const http = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    http.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    http.session = createSession();
    http.session.token = 'test-token';
    http.session.jwt = 'jwt-token';
    const command = new PortListCommand(http);

    const result = await command.create({
      name: 'Native Port List',
      comment: 'Created by native API',
      portRange: 'tcp:1-1000, udp:53',
    });

    expect(http.request).not.toHaveBeenCalled();
    expect(http.buildUrl).toHaveBeenCalledWith('api/v1/port-lists');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/port-lists',
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
          name: 'Native Port List',
          comment: 'Created by native API',
          port_ranges: [
            {protocol: 'tcp', start: 1, end: 1000},
            {protocol: 'udp', start: 53, end: 53},
          ],
        }),
      },
    );
    expect(result.data.id).toEqual('native-port-list-id');
  });

  test('should not fall back to GMP when native typed port list create fails', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'invalid range'}}),
      ok: false,
      status: 400,
    });
    testing.stubGlobal('fetch', fetchMock);
    const http = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    http.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    http.session = createSession();
    http.session.token = 'test-token';
    const command = new PortListCommand(http);

    await expect(
      command.create({name: 'Native Port List', portRange: 'tcp:1-1000'}),
    ).rejects.toThrow('Native API request failed with status 400');

    expect(fetchMock).toHaveBeenCalled();
    expect(http.request).not.toHaveBeenCalled();
  });

  test('should fall back to GMP for file or unsupported port list create shapes', async () => {
    const response = createActionResultResponse({id: 'fallback-port-list-id'});
    const http = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    http.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    http.session = createSession();
    http.session.token = 'test-token';
    const command = new PortListCommand(http);

    const result = await command.create({
      name: 'Legacy Port List',
      portRange: 'icmp:8',
    });

    expect(http.buildUrl).not.toHaveBeenCalled();
    expect(http.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'create_port_list',
        name: 'Legacy Port List',
        comment: '',
        from_file: undefined,
        port_range: 'icmp:8',
        file: undefined,
      },
    });
    expect(result.data.id).toEqual('fallback-port-list-id');
  });

  test('should allow to save a port list', async () => {
    const response = createActionResultResponse({
      action: 'save_port_list',
      id: '12345',
    });
    const http = createHttp(response);
    const command = new PortListCommand(http);
    const result = await command.save({
      id: '12345',
      name: 'Test Port List',
      comment: 'This is a test port list',
    });
    expect(result.data).toEqual({
      id: '12345',
      message: 'OK',
      action: 'save_port_list',
    });
  });

  test('should save port list metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-port-list-id'}),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const http = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    http.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    http.session = createSession();
    http.session.token = 'test-token';
    http.session.jwt = 'jwt-token';
    const command = new PortListCommand(http);

    const result = await command.save({
      id: 'port-list-id',
      name: 'Native Port List',
      comment: 'Updated by native API',
    });

    expect(http.request).not.toHaveBeenCalled();
    expect(http.buildUrl).toHaveBeenCalledWith(
      'api/v1/port-lists/port-list-id',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/port-lists/port-list-id',
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
          comment: 'Updated by native API',
          name: 'Native Port List',
        }),
      },
    );
    expect(result.data.id).toEqual('native-port-list-id');
    expect(result.data.action).toEqual('save_port_list');
    expect(result.data.message).toEqual('OK');
  });

  test('should not fall back to GMP when native port list save fails', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'duplicate'}}),
      ok: false,
      status: 409,
    });
    testing.stubGlobal('fetch', fetchMock);
    const http = createHttp(createActionResultResponse()) as ReturnType<
      typeof createHttp
    > & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    http.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    http.session = createSession();
    http.session.token = 'test-token';
    const command = new PortListCommand(http);

    await expect(
      command.save({id: 'port-list-id', name: 'Duplicate'}),
    ).rejects.toThrow('Native API request failed with status 409');

    expect(fetchMock).toHaveBeenCalled();
    expect(http.request).not.toHaveBeenCalled();
  });

  test('should clone a port list through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-port-list-clone-id'}),
      ok: true,
      status: 201,
    });
    testing.stubGlobal('fetch', fetchMock);
    const http = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    http.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    http.session = createSession();
    http.session.token = 'test-token';
    http.session.jwt = 'jwt-token';
    const command = new PortListCommand(http);

    const result = await command.clone({id: 'port-list-id'});

    expect(http.request).not.toHaveBeenCalled();
    expect(http.buildUrl).toHaveBeenCalledWith(
      'api/v1/port-lists/port-list-id/clone',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/port-lists/port-list-id/clone',
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
    expect(result.data.id).toEqual('native-port-list-clone-id');
  });

  test('should fall back to GMP when native port list clone fails', async () => {
    const response = createActionResultResponse({
      action: 'Clone Port List',
      id: 'fallback-port-list-clone-id',
      message: 'Cloned Port List',
    });
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'disabled'}}),
      ok: false,
      status: 503,
    });
    testing.stubGlobal('fetch', fetchMock);
    const http = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    http.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    http.session = createSession();
    http.session.token = 'test-token';
    const command = new PortListCommand(http);

    const result = await command.clone({id: 'port-list-id'});

    expect(fetchMock).toHaveBeenCalled();
    expect(http.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'clone',
        id: 'port-list-id',
        resource_type: 'port_list',
      },
    });
    expect(result.data.id).toEqual('fallback-port-list-clone-id');
  });

  test('should delete a port list through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: true,
      status: 204,
    });
    testing.stubGlobal('fetch', fetchMock);
    const http = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    http.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    http.session = createSession();
    http.session.token = 'test-token';
    http.session.jwt = 'jwt-token';
    const command = new PortListCommand(http);

    await command.delete({id: 'port-list-id'});

    expect(http.request).not.toHaveBeenCalled();
    expect(http.buildUrl).toHaveBeenCalledWith(
      'api/v1/port-lists/port-list-id',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/port-lists/port-list-id',
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

  test('should not fall back to GMP when native port list delete fails', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: false,
      status: 409,
    });
    testing.stubGlobal('fetch', fetchMock);
    const http = createHttp(createActionResultResponse()) as ReturnType<
      typeof createHttp
    > & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    http.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    http.session = createSession();
    http.session.token = 'test-token';
    const command = new PortListCommand(http);

    await expect(command.delete({id: 'port-list-id'})).rejects.toThrow(
      'Native API request failed with status 409',
    );

    expect(fetchMock).toHaveBeenCalled();
    expect(http.request).not.toHaveBeenCalled();
  });

  test('should allow to create a port range', async () => {
    const response = createActionResultResponse({
      action: 'create_port_range',
      id: '12345',
    });
    const http = createHttp(response);
    const command = new PortListCommand(http);
    const result = await command.createPortRange({
      portListId: '12345',
      portRangeStart: 1,
      portRangeEnd: 1000,
      portType: 'tcp',
    });
    expect(result.data).toEqual({
      id: '12345',
      message: 'OK',
      action: 'create_port_range',
    });
  });

  test('should allow to delete a port range', async () => {
    const response = createActionResultResponse({
      action: 'delete_port_range',
      id: '12345',
    });
    const entityResponse = createEntityResponse('port_list', {id: '324'});
    const http = createHttpMany([response, entityResponse]);
    const command = new PortListCommand(http);
    const result = await command.deletePortRange({
      id: '12345',
      portListId: '67890',
    });
    expect(result.data.id).toEqual('324');
  });

  test('should allow to get a port list', async () => {
    const entityResponse = createEntityResponse('port_list', {id: '324'});
    const http = createHttp(entityResponse);
    const command = new PortListCommand(http);
    const result = await command.get({id: '324'});
    expect(result.data.id).toEqual('324');
  });

  test('should allow to import a port list', async () => {
    const response = createActionResultResponse({id: '123'});
    const http = createHttp(response);
    const command = new PortListCommand(http);
    const result = await command.import({
      xmlFile: new File(['some file content'], 'portlist.xml'),
    });
    expect(result.data).toEqual({id: '123'});
  });
});
