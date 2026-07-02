/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {ScopesCommand} from 'gmp/commands/scopes';
import {createActionResultResponse, createHttp} from 'gmp/commands/testing';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('ScopesCommand tests', () => {
  test('should modify scope metadata and membership through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'scope-id'}),
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

    const cmd = new ScopesCommand(fakeHttp);
    const result = await cmd.modify({
      id: 'scope-id',
      name: 'Updated Scope',
      comment: 'metadata and membership',
      protectionRequirement: 'high',
      targetIds: ['11111111-1111-1111-1111-111111111111'],
      hostIds: [],
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/scopes/scope-id');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scopes/scope-id',
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
          name: 'Updated Scope',
          comment: 'metadata and membership',
          protection_requirement: 'high',
          target_ids: ['11111111-1111-1111-1111-111111111111'],
          host_ids: [],
        }),
      },
    );
    expect(result.data.id).toEqual('scope-id');
  });

  test('should keep unexpected scope modify payloads on GMP', async () => {
    const response = createActionResultResponse({id: 'scope-id'});
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

    const cmd = new ScopesCommand(fakeHttp);
    await cmd.modify({
      id: 'scope-id',
      name: 'Updated Scope',
      comment: 'metadata and membership',
      protectionRequirement: 'high',
      targetIds: ['11111111-1111-1111-1111-111111111111'],
      hostIds: [],
      unexpected: true,
    } as unknown as Parameters<ScopesCommand['modify']>[0]);

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'modify_scope',
        scope_id: 'scope-id',
        name: 'Updated Scope',
        comment: 'metadata and membership',
        protection_requirement: 'high',
        target_ids: '11111111-1111-1111-1111-111111111111',
        host_ids: '',
      },
    });
  });
});
