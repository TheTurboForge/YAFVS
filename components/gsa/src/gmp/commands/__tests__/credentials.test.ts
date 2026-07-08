/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import CredentialsCommand from 'gmp/commands/credentials';
import {createHttp} from 'gmp/commands/testing';
import Credential from 'gmp/models/credential';
import Filter from 'gmp/models/filter';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

const createNativeHttp = () => {
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
  return fakeHttp;
};

describe('CredentialCommand tests', () => {
  test('should fetch redacted credentials through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: 'ssh'},
        items: [
          {
            id: '6d799e1f-a81b-4b33-8090-5d4b0ed8ec77',
            name: 'SSH credential',
            comment: 'redacted metadata only',
            owner: 'admin',
            credential_type: 'usk',
            target_count: 1,
            scanner_count: 0,
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

    const cmd = new CredentialsCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=ssh type=usk'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('6d799e1f-a81b-4b33-8090-5d4b0ed8ec77');
    expect(result.data[0].name).toEqual('SSH credential');
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/credentials', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: 'ssh',
      credential_type: 'usk',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/credentials',
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
        page: {page: 1, page_size: 500, total: 2, sort: 'name', filter: ''},
        items: [{id: 'credential-1', name: 'SSH one', credential_type: 'usk'}],
      },
      {
        page: {page: 2, page_size: 500, total: 2, sort: 'name', filter: ''},
        items: [{id: 'credential-2', name: 'SSH two', credential_type: 'usk'}],
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
    const cmd = new CredentialsCommand(fakeHttp);

    const result = await cmd.getAll();

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data.map(credential => credential.id)).toEqual([
      'credential-1',
      'credential-2',
    ]);
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/credentials', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: '',
      credential_type: undefined,
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/credentials', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'name',
      filter: '',
      credential_type: undefined,
    });
  });

  test('should bulk export selected redacted credentials through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          id: 'credential-1',
          name: 'SSH one',
          credential_type: 'usk',
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          id: 'credential-2',
          name: 'SSH two',
          credential_type: 'usk',
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new CredentialsCommand(fakeHttp);

    const result = await cmd.export([
      new Credential({id: 'credential-1'}),
      new Credential({id: 'credential-2'}),
    ]);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/credentials/credential-1/export',
      {token: 'test-token'},
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/credentials/credential-2/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).credentials).toEqual([
      {id: 'credential-1', name: 'SSH one', credential_type: 'usk'},
      {id: 'credential-2', name: 'SSH two', credential_type: 'usk'},
    ]);
  });

  test('should bulk export current page redacted credentials through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 2,
            page_size: 1,
            total: 3,
            sort: 'name',
            filter: 'ssh',
          },
          items: [{id: 'credential-2', name: 'SSH two'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          id: 'credential-2',
          name: 'SSH two',
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new CredentialsCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=ssh');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/credentials', {
      token: 'test-token',
      page: 2,
      page_size: 1,
      sort: 'name',
      filter: 'ssh',
    });
    expect(JSON.parse(result.data).credentials).toEqual([
      {id: 'credential-2', name: 'SSH two'},
    ]);
  });

  test('should bulk export all filtered redacted credentials through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'name',
            filter: 'ssh',
          },
          items: [{id: 'credential-1', name: 'SSH one'}],
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
            filter: 'ssh',
          },
          items: [{id: 'credential-2', name: 'SSH two'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          id: 'credential-1',
          name: 'SSH one',
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          id: 'credential-2',
          name: 'SSH two',
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new CredentialsCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=ssh').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/credentials', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'ssh',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/credentials', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'name',
      filter: 'ssh',
    });
    expect(JSON.parse(result.data).credentials).toEqual([
      {id: 'credential-1', name: 'SSH one'},
      {id: 'credential-2', name: 'SSH two'},
    ]);
  });
});
