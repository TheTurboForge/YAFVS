/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {fetchNativeTarget, fetchNativeTargets} from 'gmp/native-api/targets';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API target list', () => {
  test('fetches target metadata and preserves credential references', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: 'target-1',
            name: 'metasploitable',
            comment: 'test target',
            hosts: ['192.168.178.50'],
            exclude_hosts: [],
            max_hosts: 1,
            alive_tests: ['Scan Config Default'],
            allow_simultaneous_ips: true,
            reverse_lookup_only: false,
            reverse_lookup_unify: false,
            port_list: {id: 'port-list-1', name: 'All IANA assigned TCP'},
            credentials: {
              ssh: {
                id: 'credential-ssh',
                name: 'metasploitable SSH',
                credential_type: 'up',
                port: 22,
              },
              smb: {
                id: 'credential-smb',
                name: 'metasploitable SMB',
                credential_type: 'up',
              },
            },
            task_count: 1,
            tasks: [{id: 'task-1', name: 'Full and fast'}],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeTargets(gmp, {
      page: 1,
      pageSize: 25,
      sort: 'name',
      filter: '',
    });

    const target = response.targets[0];
    expect(response.counts.filtered).toEqual(1);
    expect(target.name).toEqual('metasploitable');
    expect(target.hosts).toEqual(['192.168.178.50']);
    expect(target.portList?.name).toEqual('All IANA assigned TCP');
    expect(target.sshCredential?.id).toEqual('credential-ssh');
    expect(target.sshCredential?.name).toEqual('metasploitable SSH');
    expect(target.sshCredential?.port).toEqual(22);
    expect(target.smbCredential?.id).toEqual('credential-smb');
    expect(target.tasks?.[0].id).toEqual('task-1');
    expect(target.isWritable()).toEqual(true);
    expect(target.userCapabilities.mayEdit('target')).toEqual(true);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/targets', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/targets',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('fetches one target from the native detail endpoint', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'target-1',
        name: 'metasploitable',
        comment: 'detail target',
        hosts: ['192.168.178.50'],
        exclude_hosts: [],
        max_hosts: 1,
        alive_tests: ['Scan Config Default'],
        allow_simultaneous_ips: true,
        reverse_lookup_only: false,
        reverse_lookup_unify: false,
        port_list: {id: 'port-list-1', name: 'All IANA assigned TCP'},
        credentials: {},
        tasks: [{id: 'task-1', name: 'Full and fast'}],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeTarget(gmp, 'target-1');

    expect(response.target.id).toEqual('target-1');
    expect(response.target.name).toEqual('metasploitable');
    expect(response.target.tasks?.[0].id).toEqual('task-1');
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/targets/target-1', {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/targets/target-1',
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
