/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {HostCommand} from 'gmp/commands/hosts';
import {createHttp} from 'gmp/commands/testing';
import Host from 'gmp/models/host';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('HostCommand tests', () => {
  test('should create host through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        asset: {
          id: 'host-id',
          name: '192.0.2.10',
          comment: 'created',
          severity: 0,
        },
      }),
      ok: true,
      status: 201,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      path => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new HostCommand(fakeHttp);
    const result = await cmd.create({name: '192.0.2.10', comment: 'created'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/hosts');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/hosts',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({name: '192.0.2.10', comment: 'created'}),
      },
    );
    expect(result.data.id).toEqual('host-id');
  });

  test('should not fall back to GMP when native host create fails', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'disabled'}}),
      ok: false,
      status: 503,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      path => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new HostCommand(fakeHttp);

    await expect(cmd.create({name: '192.0.2.10'})).rejects.toThrow(
      'Native API request failed with status 503',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should save host comment through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        asset: {
          id: 'host-id',
          name: '192.0.2.10',
          comment: 'updated',
          severity: 0,
        },
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
      path => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new HostCommand(fakeHttp);
    const result = await cmd.save({id: 'host-id', comment: 'updated'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/hosts/host-id');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/hosts/host-id',
      {
        method: 'PATCH',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({comment: 'updated'}),
      },
    );
    expect((result.data as Host).comment).toEqual('updated');
  });

  test('should not fall back to GMP when native host save fails', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'disabled'}}),
      ok: false,
      status: 503,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      path => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new HostCommand(fakeHttp);

    await expect(cmd.save({id: 'host-id', comment: 'updated'})).rejects.toThrow(
      'Native API request failed with status 503',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should delete host through native API when available', async () => {
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
      path => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new HostCommand(fakeHttp);
    await cmd.delete({id: 'host-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/hosts/host-id');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/hosts/host-id',
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

  test('should not fall back to GMP when native host delete fails', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: false,
      status: 503,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      path => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new HostCommand(fakeHttp);

    await expect(cmd.delete({id: 'host-id'})).rejects.toThrow(
      'Native API request failed with status 503',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should export host metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        asset: {
          id: 'host-id',
          name: '192.0.2.10',
          severity: 7.5,
        },
        identifiers: [{id: 'identifier-id', name: 'hostname', value: 'web'}],
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
      path => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new HostCommand(fakeHttp);
    const result = await cmd.export({id: 'host-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/hosts/host-id/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/hosts/host-id/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      asset: {
        id: 'host-id',
        name: '192.0.2.10',
        severity: 7.5,
      },
      identifiers: [{id: 'identifier-id', name: 'hostname', value: 'web'}],
    });
  });

});
