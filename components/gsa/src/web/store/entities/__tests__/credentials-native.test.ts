/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import Credential from 'gmp/models/credential';
import Filter from 'gmp/models/filter';
import {
  fetchNativeCredential,
  fetchNativeCredentials,
} from 'gmp/native-api/credentials';
import {loadEntities, loadEntity} from 'web/store/entities/credentials';
import {createState} from 'web/store/entities/utils/testing';
import {filterIdentifier} from 'web/store/utils';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API credentials', () => {
  test('fetches redacted credential metadata as inherited Credential models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: 'df6f4d9d-cd6a-4ed2-a9cd-22564fbb87b1',
            name: 'metasploitable',
            comment: 'SSH login credential',
            owner: 'admin',
            credential_type: 'up',
            allow_insecure: false,
            target_count: 1,
            scanner_count: 0,
            created_at: '2026-07-01T00:00:00Z',
            modified_at: '2026-07-01T00:01:00Z',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeCredentials(gmp, {
      page: 1,
      pageSize: 25,
      sort: 'name',
      filter: '',
      credentialType: 'up',
    });

    const credential = response.credentials[0];
    expect(response.counts.filtered).toEqual(1);
    expect(credential.id).toEqual('df6f4d9d-cd6a-4ed2-a9cd-22564fbb87b1');
    expect(credential.name).toEqual('metasploitable');
    expect(credential.comment).toEqual('SSH login credential');
    expect(credential.owner?.name).toEqual('admin');
    expect(credential.credentialType).toEqual('up');
    expect(credential.login).toBeUndefined();
    expect(credential.credentialStore).toBeUndefined();
    expect(credential.privateKeyInfo).toBeUndefined();
    expect(credential.isInUse()).toEqual(true);
    expect(credential.userCapabilities.mayEdit('credential')).toEqual(true);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/credentials', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: '',
      credential_type: 'up',
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

  test('fetches redacted credential detail backlinks without secret fields', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'df6f4d9d-cd6a-4ed2-a9cd-22564fbb87b1',
        name: 'metasploitable',
        owner: 'admin',
        credential_type: 'up',
        target_count: 1,
        scanner_count: 1,
        targets: [
          {
            id: '9c7781dd-25e5-4f70-8b3d-a6b9180a0001',
            name: 'metasploitable target',
            use_type: 'ssh',
            port: 22,
          },
        ],
        scanners: [
          {
            id: '08b69003-5fc2-4037-a479-93b440211c73',
            name: 'OpenVAS Default',
            use_type: 'scanner',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const credential = await fetchNativeCredential(
      gmp,
      'df6f4d9d-cd6a-4ed2-a9cd-22564fbb87b1',
    );

    expect(credential.targets).toHaveLength(1);
    expect(credential.targets[0].id).toEqual(
      '9c7781dd-25e5-4f70-8b3d-a6b9180a0001',
    );
    expect(credential.targets[0].name).toEqual('metasploitable target');
    expect(credential.scanners).toHaveLength(1);
    expect(credential.scanners[0].name).toEqual('OpenVAS Default');
    expect(credential.login).toBeUndefined();
    expect(credential.privateKeyInfo).toBeUndefined();
    expect(credential.publicKeyInfo).toBeUndefined();
    expect(credential.credentialStore).toBeUndefined();
  });

  test('loads credential list store entries through same-origin native API', async () => {
    const filter = Filter.fromString('first=1 rows=10 sort=name');
    const rootState = createState('credential', {
      isLoading: {
        [filterIdentifier(filter)]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 10, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: 'df6f4d9d-cd6a-4ed2-a9cd-22564fbb87b1',
            name: 'metasploitable',
            credential_type: 'up',
            target_count: 1,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      ...createGmp(),
      credentials: {
        get: testing.fn().mockRejectedValue(new Error('inherited fallback used')),
      },
    };

    await loadEntities(gmp)(filter)(dispatch, getState);

    expect(gmp.credentials.get).not.toHaveBeenCalled();
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/credentials', {
      token: 'test-token',
      page: 1,
      page_size: 10,
      sort: 'name',
      filter: '',
    });
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITIES_LOADING_SUCCESS');
    expect(successAction.counts.filtered).toEqual(1);
    expect(successAction.data[0]).toBeInstanceOf(Credential);
    expect(successAction.data[0].name).toEqual('metasploitable');
    expect(successAction.data[0].login).toBeUndefined();
  });

  test('loads credential detail store entries through redacted native API', async () => {
    const id = 'df6f4d9d-cd6a-4ed2-a9cd-22564fbb87b1';
    const rootState = createState('credential', {
      isLoading: {
        [id]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id,
        name: 'metasploitable',
        credential_type: 'up',
        target_count: 1,
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      ...createGmp(),
      credential: {
        get: testing.fn().mockRejectedValue(new Error('inherited fallback used')),
      },
    };

    await loadEntity(gmp)(id)(dispatch, getState);

    expect(gmp.credential.get).not.toHaveBeenCalled();
    expect(gmp.buildUrl).toHaveBeenCalledWith(`api/v1/credentials/${id}`, {
      token: 'test-token',
    });
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITY_LOADING_SUCCESS');
    expect(successAction.id).toEqual(id);
    expect(successAction.data).toBeInstanceOf(Credential);
    expect(successAction.data.name).toEqual('metasploitable');
    expect(successAction.data.login).toBeUndefined();
  });
});
