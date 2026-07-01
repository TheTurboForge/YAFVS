/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import CredentialsCommand from 'gmp/commands/credentials';
import {createHttp, createEntitiesResponse} from 'gmp/commands/testing';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('CredentialCommand tests', () => {
  test('should fetch credentials', async () => {
    const response = createEntitiesResponse('credential', [
      {_id: '1', name: 'Credential 1'},
      {_id: '2', name: 'Credential 2'},
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new CredentialsCommand(fakeHttp);
    const resp = await cmd.get();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_credentials'},
    });
    expect(resp.data).toEqual([
      expect.objectContaining({id: '1', name: 'Credential 1'}),
      expect.objectContaining({id: '2', name: 'Credential 2'}),
    ]);
  });

  test('should fetch credentials with custom filter', async () => {
    const response = createEntitiesResponse('credential', [
      {_id: '2', name: 'Credential 2'},
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new CredentialsCommand(fakeHttp);
    const resp = await cmd.get({filter: "name='Credential 2'"});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_credentials',
        filter: "name='Credential 2'",
      },
    });
    expect(resp.data).toEqual([
      expect.objectContaining({id: '2', name: 'Credential 2'}),
    ]);
  });

  test('should fetch all credentials', async () => {
    const response = createEntitiesResponse('credential', [
      {_id: '3', name: 'Credential 3'},
      {_id: '4', name: 'Credential 4'},
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new CredentialsCommand(fakeHttp);
    const resp = await cmd.getAll();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_credentials',
        filter: 'first=1 rows=-1',
      },
    });
    expect(resp.data).toEqual([
      expect.objectContaining({id: '3', name: 'Credential 3'}),
      expect.objectContaining({id: '4', name: 'Credential 4'}),
    ]);
  });

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
});
