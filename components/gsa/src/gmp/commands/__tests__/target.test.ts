/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import TargetCommand from 'gmp/commands/target';
import {
  createActionResultResponse,
  createEntityResponse,
  createHttp,
  createResponse,
} from 'gmp/commands/testing';
import type Http from 'gmp/http/http';
import {ResponseRejection} from 'gmp/http/rejection';
import {createSession} from 'gmp/testing';
import {SCAN_CONFIG_DEFAULT} from 'gmp/models/target';
import {NO_VALUE, YES_VALUE} from 'gmp/parser';
import {UNSET_VALUE} from 'web/utils/Render';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('TargetCommand tests', () => {
  test('should return single target through GMP when native API is unavailable', async () => {
    const response = createEntityResponse('target', {_id: 'target-id'});
    const fakeHttp = createHttp(response);
    const cmd = new TargetCommand(fakeHttp);

    const result = await cmd.get({id: 'target-id'});

    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_target',
        target_id: 'target-id',
      },
    });
    expect(result.data.id).toEqual('target-id');
  });

  test('should fetch single target through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'target-id',
        name: 'Native target',
        hosts: ['192.0.2.10'],
        exclude_hosts: ['192.0.2.11'],
        alive_tests: ['ICMP Ping'],
        allow_simultaneous_ips: true,
        reverse_lookup_only: false,
        reverse_lookup_unify: true,
        port_list: {id: 'port-list-id', name: 'All IANA assigned TCP'},
        credentials: {
          ssh: {
            id: 'ssh-credential-id',
            name: 'SSH',
            port: 2222,
            host_key_pins: [
              {
                host: '192.0.2.10',
                fingerprint:
                  'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              },
            ],
          },
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
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new TargetCommand(fakeHttp);

    const result = await cmd.get({id: 'target-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/targets/target-id', {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/targets/target-id',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data.id).toEqual('target-id');
    expect(result.data.name).toEqual('Native target');
    expect(result.data.hosts).toEqual(['192.0.2.10']);
    expect(result.data.excludeHosts).toEqual(['192.0.2.11']);
    expect(result.data.sshCredential?.id).toEqual('ssh-credential-id');
    expect(result.data.sshCredential?.port).toEqual(2222);
    expect(result.data.sshCredential?.hostKeyPins).toEqual([
      {
        host: '192.0.2.10',
        fingerprint: 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      },
    ]);
  });

  test('should not fall back to GMP when native target detail fails', async () => {
    testing.stubGlobal(
      'fetch',
      testing.fn().mockResolvedValue({
        json: testing.fn().mockResolvedValue({message: 'missing'}),
        ok: false,
        status: 404,
      }),
    );
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new TargetCommand(fakeHttp);

    await expect(cmd.get({id: 'missing-target'})).rejects.toThrow(
      'Native API request failed with status 404',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should export target metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'target-id',
        name: 'Native target',
        hosts: ['192.0.2.10'],
        credentials: [{id: 'credential-id', name: 'Credential', type: 'ssh'}],
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
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new TargetCommand(fakeHttp);

    const result = await cmd.export({id: 'target-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/targets/target-id/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/targets/target-id/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: 'target-id',
      name: 'Native target',
      hosts: ['192.0.2.10'],
      credentials: [{id: 'credential-id', name: 'Credential', type: 'ssh'}],
    });
  });

  test('should clone target through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-target-clone-id'}),
      ok: true,
      status: 201,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new TargetCommand(fakeHttp);

    const result = await cmd.clone({id: 'target-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/targets/target-id/clone',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/targets/target-id/clone',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-YAFVS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({}),
      },
    );
    expect(result.data.id).toEqual('native-target-clone-id');
  });

  test('should not fall back to GMP when native target clone fails', async () => {
    const response = createActionResultResponse({
      action: 'Clone Target',
      id: 'fallback-target-clone-id',
      message: 'Cloned Target',
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
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    const cmd = new TargetCommand(fakeHttp);

    await expect(cmd.clone({id: 'target-id'})).rejects.toThrow(
      'Native API request failed with status 503',
    );
    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should delete target through native API when available', async () => {
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
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new TargetCommand(fakeHttp);

    await cmd.delete({id: 'target-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/targets/target-id');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/targets/target-id',
      {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'X-YAFVS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('should not fall back to GMP when native target delete fails', async () => {
    const response = createActionResultResponse({id: 'fallback-target-id'});
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
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    const cmd = new TargetCommand(fakeHttp);

    await expect(cmd.delete({id: 'target-id'})).rejects.toThrow(
      'Native API request failed with status 409',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should create target', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new TargetCommand(fakeHttp);
    const resp = await cmd.create({
      allowSimultaneousIPs: true,
      name: 'name',
      comment: 'comment',
      targetSource: 'manual',
      targetExcludeSource: 'manual',
      hostsFilter: undefined,
      hosts: '123.456, 678.9',
      excludeHosts: '',
      reverseLookupOnly: false,
      reverseLookupUnify: true,
      portListId: 'pl_id1',
      aliveTests: [SCAN_CONFIG_DEFAULT],
      port: 22,
      sshCredentialId: 'ssh_id',
      sshElevateCredentialId: '0',
      smbCredentialId: '0',
      esxiCredentialId: '0',
      snmpCredentialId: '0',
      krb5CredentialId: '0',
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'create_target',
        allow_simultaneous_ips: 1,
        'alive_tests:': ['Scan Config Default'],
        comment: 'comment',
        esxi_credential_id: '0',
        exclude_file: undefined,
        exclude_hosts: '',
        file: undefined,
        hosts: '123.456, 678.9',
        hosts_filter: undefined,
        name: 'name',
        port: 22,
        port_list_id: 'pl_id1',
        reverse_lookup_unify: YES_VALUE,
        reverse_lookup_only: NO_VALUE,
        smb_credential_id: '0',
        snmp_credential_id: '0',
        ssh_credential_id: 'ssh_id',
        ssh_elevate_credential_id: '0',
        target_exclude_source: 'manual',
        target_source: 'manual',
        krb5_credential_id: '0',
      },
    });
    expect(resp.data.id).toEqual('foo');
  });

  test('should create simple manual target through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-target-id'}),
      ok: true,
      status: 201,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new TargetCommand(fakeHttp);

    const result = await cmd.create({
      allowSimultaneousIPs: true,
      name: 'Native Target',
      comment: 'comment',
      targetSource: 'manual',
      targetExcludeSource: 'manual',
      hosts: '192.0.2.10, example.test',
      excludeHosts: '',
      reverseLookupOnly: false,
      reverseLookupUnify: true,
      portListId: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
      aliveTests: [SCAN_CONFIG_DEFAULT],
      port: 22,
      sshCredentialId: UNSET_VALUE,
      sshElevateCredentialId: UNSET_VALUE,
      smbCredentialId: UNSET_VALUE,
      esxiCredentialId: UNSET_VALUE,
      snmpCredentialId: UNSET_VALUE,
      krb5CredentialId: UNSET_VALUE,
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/targets');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/targets',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-YAFVS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({
          name: 'Native Target',
          comment: 'comment',
          port_list_id: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
          hosts: ['192.0.2.10', 'example.test'],
          exclude_hosts: [],
          alive_tests: [SCAN_CONFIG_DEFAULT],
          allow_simultaneous_ips: true,
          reverse_lookup_only: false,
          reverse_lookup_unify: true,
        }),
      },
    );
    expect(result.data.id).toEqual('native-target-id');
  });

  test('should create target with credential references through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-target-id'}),
      ok: true,
      status: 201,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new TargetCommand(fakeHttp);

    const result = await cmd.create({
      allowSimultaneousIPs: true,
      name: 'name',
      comment: 'comment',
      targetSource: 'manual',
      targetExcludeSource: 'manual',
      hosts: '192.0.2.10',
      excludeHosts: '',
      reverseLookupOnly: false,
      reverseLookupUnify: true,
      portListId: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
      aliveTests: [SCAN_CONFIG_DEFAULT],
      port: 2222,
      sshCredentialId: '54b05b45-02be-4123-9b05-b4502be11234',
      sshElevateCredentialId: UNSET_VALUE,
      sshHostKeyPins:
        '192.0.2.10 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      smbCredentialId: UNSET_VALUE,
      esxiCredentialId: UNSET_VALUE,
      snmpCredentialId: UNSET_VALUE,
      krb5CredentialId: UNSET_VALUE,
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/targets');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/targets',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-YAFVS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({
          name: 'name',
          comment: 'comment',
          port_list_id: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
          hosts: ['192.0.2.10'],
          exclude_hosts: [],
          alive_tests: [SCAN_CONFIG_DEFAULT],
          allow_simultaneous_ips: true,
          reverse_lookup_only: false,
          reverse_lookup_unify: true,
          credentials: {
            ssh: {
              id: '54b05b45-02be-4123-9b05-b4502be11234',
              port: 2222,
              host_key_pins: [
                {
                  host: '192.0.2.10',
                  fingerprint:
                    'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                },
              ],
            },
          },
        }),
      },
    );
    expect(result.data.id).toEqual('native-target-id');
  });

  test('should reject native SSH target creation without host-key pins instead of falling back to GMP', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    const cmd = new TargetCommand(fakeHttp);

    await expect(
      cmd.create({
        aliveTests: [SCAN_CONFIG_DEFAULT],
        allowSimultaneousIPs: true,
        name: 'Pinned SSH target',
        targetSource: 'manual',
        targetExcludeSource: 'manual',
        hosts: '192.0.2.10',
        excludeHosts: '',
        reverseLookupOnly: false,
        reverseLookupUnify: false,
        portListId: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
        port: 22,
        sshCredentialId: '54b05b45-02be-4123-9b05-b4502be11234',
      }),
    ).rejects.toThrow('require valid per-IP OpenSSH SHA-256 host-key pins');
    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should create target with non-ssh credential references through native API when default ssh port is present', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-target-id'}),
      ok: true,
      status: 201,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new TargetCommand(fakeHttp);

    await cmd.create({
      allowSimultaneousIPs: true,
      name: 'name',
      comment: 'comment',
      targetSource: 'manual',
      targetExcludeSource: 'manual',
      hosts: '192.0.2.10',
      excludeHosts: '',
      reverseLookupOnly: false,
      reverseLookupUnify: true,
      portListId: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
      aliveTests: [SCAN_CONFIG_DEFAULT],
      port: 22,
      sshCredentialId: UNSET_VALUE,
      sshElevateCredentialId: UNSET_VALUE,
      smbCredentialId: '54b05b45-02be-4123-9b05-b4502be11235',
      esxiCredentialId: UNSET_VALUE,
      snmpCredentialId: UNSET_VALUE,
      krb5CredentialId: UNSET_VALUE,
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/targets',
      expect.objectContaining({
        body: JSON.stringify({
          name: 'name',
          comment: 'comment',
          port_list_id: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
          hosts: ['192.0.2.10'],
          exclude_hosts: [],
          alive_tests: [SCAN_CONFIG_DEFAULT],
          allow_simultaneous_ips: true,
          reverse_lookup_only: false,
          reverse_lookup_unify: true,
          credentials: {
            smb: {
              id: '54b05b45-02be-4123-9b05-b4502be11235',
            },
          },
        }),
      }),
    );
  });

  test('should keep invalid credential target creates on GMP when native API is available', async () => {
    const response = createActionResultResponse();
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    const cmd = new TargetCommand(fakeHttp);

    await cmd.create({
      allowSimultaneousIPs: true,
      name: 'name',
      comment: 'comment',
      targetSource: 'manual',
      targetExcludeSource: 'manual',
      hosts: '192.0.2.10',
      excludeHosts: '',
      reverseLookupOnly: false,
      reverseLookupUnify: true,
      portListId: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
      aliveTests: [SCAN_CONFIG_DEFAULT],
      sshCredentialId: UNSET_VALUE,
      sshElevateCredentialId: '54b05b45-02be-4123-9b05-b4502be11234',
      smbCredentialId: UNSET_VALUE,
      esxiCredentialId: UNSET_VALUE,
      snmpCredentialId: UNSET_VALUE,
      krb5CredentialId: UNSET_VALUE,
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: expect.objectContaining({
        cmd: 'create_target',
        hosts: '192.0.2.10',
        ssh_elevate_credential_id: UNSET_VALUE,
      }),
    });
  });

  test('should keep unsupported host target creates on GMP when native API is available', async () => {
    const response = createActionResultResponse();
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    const cmd = new TargetCommand(fakeHttp);

    await cmd.create({
      allowSimultaneousIPs: true,
      name: 'name',
      comment: 'comment',
      targetSource: 'manual',
      targetExcludeSource: 'manual',
      hosts: '192.0.2.0/24',
      excludeHosts: '',
      reverseLookupOnly: false,
      reverseLookupUnify: true,
      portListId: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
      aliveTests: [SCAN_CONFIG_DEFAULT],
      port: 22,
      sshCredentialId: UNSET_VALUE,
      sshElevateCredentialId: UNSET_VALUE,
      smbCredentialId: UNSET_VALUE,
      esxiCredentialId: UNSET_VALUE,
      snmpCredentialId: UNSET_VALUE,
      krb5CredentialId: UNSET_VALUE,
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: expect.objectContaining({
        cmd: 'create_target',
        hosts: '192.0.2.0/24',
      }),
    });
  });

  test.each([
    {
      name: 'missing port list',
      message: 'Failed to find port_list XYZ',
      expectedMessage:
        'Failed to create a new Target because the default Port List is not available. This issue may be due to the feed not having completed its synchronization.\nPlease try again shortly.',
    },
    {
      name: 'missing scan config',
      message: 'Failed to find config XYZ',
      expectedMessage:
        'Failed to create a new Task because the default Scan Config is not available. This issue may be due to the feed not having completed its synchronization.\nPlease try again shortly.',
    },
  ])(
    'should not create new target while feed is not available: $name',
    async ({message, expectedMessage}) => {
      const xhr = {
        status: 404,
      } as XMLHttpRequest;
      const rejection = new ResponseRejection(xhr, message);
      const request = testing.fn().mockRejectedValue(rejection);
      const fakeHttp = {
        request,
      } as unknown as Http;

      const cmd = new TargetCommand(fakeHttp);
      await expect(
        cmd.create({
          allowSimultaneousIPs: true,
          name: 'name',
          comment: 'comment',
          targetSource: 'manual',
          targetExcludeSource: 'manual',
          hostsFilter: undefined,
          hosts: '123.456, 678.9',
          excludeHosts: '',
          reverseLookupOnly: false,
          reverseLookupUnify: true,
          portListId: 'pl_id1',
          aliveTests: [SCAN_CONFIG_DEFAULT],
          port: 22,
          sshCredentialId: 'ssh_id',
          sshElevateCredentialId: '0',
          smbCredentialId: '0',
          esxiCredentialId: '0',
          snmpCredentialId: '0',
          krb5CredentialId: '0',
        }),
      ).rejects.toThrow(expectedMessage);
      expect(request).toHaveBeenCalledTimes(1);
    },
  );

  test('should nullify ssh_elevate_credential in create command', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new TargetCommand(fakeHttp);
    const resp = await cmd.create({
      allowSimultaneousIPs: true,
      name: 'name',
      comment: 'comment',
      targetSource: 'manual',
      targetExcludeSource: 'manual',
      hostsFilter: undefined,
      hosts: '123.456, 678.9',
      excludeHosts: '',
      reverseLookupOnly: false,
      reverseLookupUnify: true,
      portListId: 'pl_id1',
      aliveTests: [SCAN_CONFIG_DEFAULT],
      port: 22,
      sshCredentialId: '0',
      sshElevateCredentialId: 'ssh_elevate_id',
      smbCredentialId: '0',
      esxiCredentialId: '0',
      snmpCredentialId: '0',
      krb5CredentialId: '0',
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'create_target',
        allow_simultaneous_ips: YES_VALUE,
        'alive_tests:': ['Scan Config Default'],
        comment: 'comment',
        esxi_credential_id: '0',
        exclude_file: undefined,
        exclude_hosts: '',
        file: undefined,
        hosts: '123.456, 678.9',
        hosts_filter: undefined,
        name: 'name',
        port: 22,
        port_list_id: 'pl_id1',
        reverse_lookup_unify: YES_VALUE,
        reverse_lookup_only: NO_VALUE,
        smb_credential_id: '0',
        snmp_credential_id: '0',
        ssh_credential_id: '0',
        ssh_elevate_credential_id: '0',
        target_exclude_source: 'manual',
        target_source: 'manual',
        krb5_credential_id: '0',
      },
    });
    const {data} = resp;
    expect(data.id).toEqual('foo');
  });

  test('should save target', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new TargetCommand(fakeHttp);
    const resp = await cmd.save({
      id: 'target_id1',
      allowSimultaneousIPs: true,
      name: 'name',
      comment: 'comment',
      targetSource: 'manual',
      targetExcludeSource: 'manual',
      hostsFilter: undefined,
      excludeFile: undefined,
      hosts: '123.456, 678.9',
      excludeHosts: '',
      reverseLookupOnly: false,
      reverseLookupUnify: true,
      portListId: 'pl_id1',
      aliveTests: [SCAN_CONFIG_DEFAULT],
      port: 22,
      sshCredentialId: 'ssh_id',
      sshElevateCredentialId: '0',
      smbCredentialId: '0',
      esxiCredentialId: '0',
      snmpCredentialId: '0',
      krb5CredentialId: '0',
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_target',
        allow_simultaneous_ips: YES_VALUE,
        'alive_tests:': ['Scan Config Default'],
        comment: 'comment',
        esxi_credential_id: '0',
        exclude_file: undefined,
        exclude_hosts: '',
        file: undefined,
        hosts: '123.456, 678.9',
        hosts_filter: undefined,
        name: 'name',
        port: 22,
        port_list_id: 'pl_id1',
        reverse_lookup_unify: YES_VALUE,
        reverse_lookup_only: NO_VALUE,
        smb_credential_id: '0',
        snmp_credential_id: '0',
        ssh_credential_id: 'ssh_id',
        ssh_elevate_credential_id: '0',
        krb5_credential_id: '0',
        target_exclude_source: 'manual',
        target_id: 'target_id1',
        target_source: 'manual',
      },
    });
    const {data} = resp;
    expect(data.id).toEqual('foo');
  });

  test('should save target metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'target_id1', name: 'updated'}),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new TargetCommand(fakeHttp);

    const result = await cmd.save({
      id: 'target_id1',
      name: 'updated',
      comment: 'metadata only',
      port: 22,
      sshHostKeyPins: '',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/targets/target_id1');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/targets/target_id1',
      {
        method: 'PATCH',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-YAFVS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({
          name: 'updated',
          comment: 'metadata only',
        }),
      },
    );
    expect(result.data.id).toEqual('target_id1');
  });

  test('should save scan-input target changes through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'target_id1', name: 'updated'}),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new TargetCommand(fakeHttp);

    const result = await cmd.save({
      id: 'target_id1',
      allowSimultaneousIPs: true,
      name: 'updated',
      comment: 'comment',
      targetSource: 'manual',
      targetExcludeSource: 'manual',
      hosts: '192.0.2.10, example.test',
      excludeHosts: '',
      reverseLookupOnly: false,
      reverseLookupUnify: true,
      portListId: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
      aliveTests: [SCAN_CONFIG_DEFAULT],
      port: 22,
      sshCredentialId: '54b05b45-02be-4123-9b05-b4502be11234',
      sshElevateCredentialId: UNSET_VALUE,
      sshHostKeyPins:
        '192.0.2.10 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      smbCredentialId: UNSET_VALUE,
      esxiCredentialId: UNSET_VALUE,
      snmpCredentialId: UNSET_VALUE,
      krb5CredentialId: UNSET_VALUE,
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/targets/target_id1');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/targets/target_id1',
      {
        method: 'PATCH',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-YAFVS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({
          name: 'updated',
          comment: 'comment',
          alive_tests: [SCAN_CONFIG_DEFAULT],
          allow_simultaneous_ips: true,
          reverse_lookup_only: false,
          reverse_lookup_unify: true,
          port_list_id: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
          hosts: ['192.0.2.10', 'example.test'],
          exclude_hosts: [],
          credentials: {
            ssh: {
              id: '54b05b45-02be-4123-9b05-b4502be11234',
              port: 22,
              host_key_pins: [
                {
                  host: '192.0.2.10',
                  fingerprint:
                    'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                },
              ],
            },
            ssh_elevate: null,
            smb: null,
            esxi: null,
            snmp: null,
            krb5: null,
          },
        }),
      },
    );
    expect(result.data.id).toEqual('target_id1');
  });

  test('should keep unsupported host target saves on GMP when native API is available', async () => {
    const response = createActionResultResponse();
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    const cmd = new TargetCommand(fakeHttp);

    await cmd.save({
      id: 'target_id1',
      allowSimultaneousIPs: true,
      name: 'name',
      comment: 'comment',
      targetSource: 'manual',
      targetExcludeSource: 'manual',
      hosts: '192.0.2.0/24',
      excludeHosts: '',
      reverseLookupOnly: false,
      reverseLookupUnify: true,
      portListId: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
      aliveTests: [SCAN_CONFIG_DEFAULT],
      port: 22,
      sshCredentialId: UNSET_VALUE,
      sshElevateCredentialId: UNSET_VALUE,
      smbCredentialId: UNSET_VALUE,
      esxiCredentialId: UNSET_VALUE,
      snmpCredentialId: UNSET_VALUE,
      krb5CredentialId: UNSET_VALUE,
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: expect.objectContaining({
        cmd: 'save_target',
        target_id: 'target_id1',
        hosts: '192.0.2.0/24',
        ssh_credential_id: UNSET_VALUE,
      }),
    });
  });

  test.each([
    {
      name: 'missing port list',
      message: 'Failed to find port_list XYZ',
      expectedMessage:
        'Failed to create a new Target because the default Port List is not available. This issue may be due to the feed not having completed its synchronization.\nPlease try again shortly.',
    },
    {
      name: 'missing scan config',
      message: 'Failed to find config XYZ',
      expectedMessage:
        'Failed to create a new Task because the default Scan Config is not available. This issue may be due to the feed not having completed its synchronization.\nPlease try again shortly.',
    },
  ])(
    'should not save target while feed is not available: $name',
    async ({message, expectedMessage}) => {
      const xhr = {
        status: 404,
      } as XMLHttpRequest;
      const rejection = new ResponseRejection(xhr, message);
      const request = testing.fn().mockRejectedValue(rejection);
      const fakeHttp = {
        request,
      } as unknown as Http;

      const cmd = new TargetCommand(fakeHttp);
      await expect(
        cmd.save({
          id: 'target_id1',
          allowSimultaneousIPs: true,
          name: 'name',
          comment: 'comment',
          targetSource: 'manual',
          targetExcludeSource: 'manual',
          hostsFilter: undefined,
          excludeFile: undefined,
          hosts: '123.456, 678.9',
          excludeHosts: '',
          reverseLookupOnly: false,
          reverseLookupUnify: true,
          portListId: 'pl_id1',
          aliveTests: [SCAN_CONFIG_DEFAULT],
          port: 22,
          sshCredentialId: UNSET_VALUE,
          sshElevateCredentialId: 'ssh_elevate_id',
          smbCredentialId: UNSET_VALUE,
          esxiCredentialId: UNSET_VALUE,
          snmpCredentialId: UNSET_VALUE,
          krb5CredentialId: UNSET_VALUE,
        }),
      ).rejects.toThrow(expectedMessage);
      expect(request).toHaveBeenCalledTimes(1);
    },
  );

  test('should nullify ssh_elevate_credential if ssh_credential is not set in save command', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new TargetCommand(fakeHttp);
    const resp = await cmd.save({
      id: 'target_id1',
      name: 'name',
      sshCredentialId: undefined,
      sshElevateCredentialId: 'ssh_elevate_id',
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_target',
        allow_simultaneous_ips: undefined,
        'alive_tests:': undefined,
        comment: undefined,
        esxi_credential_id: undefined,
        exclude_file: undefined,
        exclude_hosts: undefined,
        file: undefined,
        hosts: undefined,
        name: 'name',
        port: undefined,
        port_list_id: undefined,
        reverse_lookup_unify: undefined,
        reverse_lookup_only: undefined,
        smb_credential_id: undefined,
        snmp_credential_id: undefined,
        ssh_credential_id: undefined,
        ssh_elevate_credential_id: undefined,
        target_exclude_source: undefined,
        target_id: 'target_id1',
        target_source: undefined,
        krb5_credential_id: undefined,
      },
    });
    const {data} = resp;
    expect(data.id).toEqual('foo');
  });
});
