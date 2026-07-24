/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import TargetCommand from 'gmp/commands/target';
import {createActionResultResponse, createHttp} from 'gmp/commands/testing';
import {SCAN_CONFIG_DEFAULT, type AliveTest} from 'gmp/models/target';
import {createSession} from 'gmp/testing';
import {UNSET_VALUE} from 'web/utils/Render';

afterEach(() => {
  testing.unstubAllGlobals();
});

const nativeHttp = () => {
  const http = createHttp(undefined) as ReturnType<typeof createHttp> & {
    buildUrl: ReturnType<typeof testing.fn>;
    session: ReturnType<typeof createSession>;
  };
  http.buildUrl = testing.fn((path: string) => `https://yafvs.example/${path}`);
  http.session = createSession();
  http.session.token = 'test-token';
  http.session.jwt = 'jwt-token';
  return http;
};

const nativeWriteParams = () => ({
  allowSimultaneousIPs: true,
  aliveTests: [SCAN_CONFIG_DEFAULT] as AliveTest[],
  esxiCredentialId: UNSET_VALUE,
  excludeHosts: '',
  hosts: '192.0.2.10',
  krb5CredentialId: UNSET_VALUE,
  name: 'Native Target',
  port: 22,
  portListId: 'port-list-id',
  reverseLookupOnly: false,
  reverseLookupUnify: false,
  smbCredentialId: UNSET_VALUE,
  snmpCredentialId: UNSET_VALUE,
  sshCredentialId: UNSET_VALUE,
  sshElevateCredentialId: UNSET_VALUE,
  targetExcludeSource: 'manual' as const,
  targetSource: 'manual' as const,
});

describe('TargetCommand tests', () => {
  test('should refuse target detail locally when native API is unavailable', async () => {
    const fakeHttp = createHttp(undefined);
    const cmd = new TargetCommand(fakeHttp);

    await expect(cmd.get({id: 'target-id'})).rejects.toThrow(
      'Native target API is required for target command',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test.each(['create', 'save'] as const)(
    'should refuse target %s locally when native API is unavailable',
    async operation => {
      const fakeHttp = createHttp(undefined);
      const cmd = new TargetCommand(fakeHttp);
      const params = nativeWriteParams();

      await expect(
        operation === 'create'
          ? cmd.create(params)
          : cmd.save({id: 'target-id', ...params}),
      ).rejects.toThrow('Native target API is required for target command');

      expect(fakeHttp.request).not.toHaveBeenCalled();
    },
  );

  test.each(['create', 'save'] as const)(
    'should propagate native target %s failure without a GMP request',
    async operation => {
      const fetchMock = testing.fn().mockResolvedValue({
        ok: false,
        status: 409,
      });
      testing.stubGlobal('fetch', fetchMock);
      const fakeHttp = nativeHttp();
      const cmd = new TargetCommand(fakeHttp);
      const params = nativeWriteParams();

      await expect(
        operation === 'create'
          ? cmd.create(params)
          : cmd.save({id: 'target-id', ...params}),
      ).rejects.toThrow('Native API request failed with status 409');

      expect(fakeHttp.request).not.toHaveBeenCalled();
    },
  );

  test('should reject unreadable save files without GMP fallback', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = nativeHttp();
    const file = {
      size: 16,
      text: testing.fn().mockRejectedValue(new Error('read failed')),
    } as unknown as File;

    await expect(
      new TargetCommand(fakeHttp).save({
        id: 'target-id',
        ...nativeWriteParams(),
        file,
        targetSource: 'file',
      }),
    ).rejects.toThrow('Native target source preparation failed');

    expect(file.text).toHaveBeenCalledOnce();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject oversized native save bodies without GMP fallback', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = nativeHttp();
    const hosts = Array.from(
      {length: 4095},
      (_, index) => `host-${index}-${'a'.repeat(55)}`,
    ).join(',');

    await expect(
      new TargetCommand(fakeHttp).save({
        id: 'target-id',
        ...nativeWriteParams(),
        hosts,
      }),
    ).rejects.toThrow(
      'Native target request exceeds the native request-size limit',
    );

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject invalid save credential links without GMP fallback', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = nativeHttp();

    await expect(
      new TargetCommand(fakeHttp).save({
        id: 'target-id',
        ...nativeWriteParams(),
        sshCredentialId: undefined,
        sshElevateCredentialId: '54b05b45-02be-4123-9b05-b4502be11234',
      }),
    ).rejects.toThrow('Native target request conversion failed');

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test.each([undefined, '', '   '])(
    'should reject invalid target deletion ID %p before native request',
    async id => {
      const fetchMock = testing.fn();
      testing.stubGlobal('fetch', fetchMock);
      const fakeHttp = createHttp(undefined) as ReturnType<
        typeof createHttp
      > & {
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

      await expect(cmd.delete({id: id as string})).rejects.toThrow(
        'Target ID must be a non-empty string',
      );

      expect(fakeHttp.buildUrl).not.toHaveBeenCalled();
      expect(fetchMock).not.toHaveBeenCalled();
      expect(fakeHttp.request).not.toHaveBeenCalled();
    },
  );

  test('should reject host asset IDs under a manual source without GMP fallback', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(createActionResultResponse()) as ReturnType<
      typeof createHttp
    > & {
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
        allowSimultaneousIPs: true,
        name: 'Malformed Asset Target',
        targetSource: 'manual',
        targetExcludeSource: 'manual',
        hosts: '192.0.2.10',
        hostAssetIds: ['11111111-1111-4111-8111-111111111111'],
        excludeHosts: '',
        reverseLookupOnly: false,
        reverseLookupUnify: false,
        portListId: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
        aliveTests: [SCAN_CONFIG_DEFAULT],
        port: 22,
      }),
    ).rejects.toThrow('requires the native asset_hosts source');
    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject host asset IDs when native API is unavailable', async () => {
    const fakeHttp = createHttp(createActionResultResponse());
    const cmd = new TargetCommand(fakeHttp);

    await expect(
      cmd.create({
        allowSimultaneousIPs: true,
        name: 'Asset Target',
        targetSource: 'asset_hosts',
        targetExcludeSource: 'manual',
        hostAssetIds: ['11111111-1111-4111-8111-111111111111'],
        excludeHosts: '',
        reverseLookupOnly: false,
        reverseLookupUnify: false,
        portListId: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
        aliveTests: [SCAN_CONFIG_DEFAULT],
        port: 22,
      }),
    ).rejects.toThrow('Native target API is required');
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject an oversized host asset request without GMP fallback', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(createActionResultResponse()) as ReturnType<
      typeof createHttp
    > & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    const cmd = new TargetCommand(fakeHttp);
    const hostAssetIds = Array.from(
      {length: 100},
      (_, index) => `${index}-${'x'.repeat(4096)}`,
    );

    await expect(
      cmd.create({
        allowSimultaneousIPs: true,
        name: 'Oversized Asset Target',
        targetSource: 'asset_hosts',
        targetExcludeSource: 'manual',
        hostAssetIds,
        excludeHosts: '',
        reverseLookupOnly: false,
        reverseLookupUnify: false,
        portListId: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
        aliveTests: [SCAN_CONFIG_DEFAULT],
        port: 22,
      }),
    ).rejects.toThrow('exceeds the native request-size limit');
    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject host asset IDs on save without inherited fallback', async () => {
    const fakeHttp = createHttp(createActionResultResponse());
    const cmd = new TargetCommand(fakeHttp);

    await expect(
      cmd.save({
        id: 'target-id',
        name: 'Asset Target',
        targetSource: 'manual',
        hostAssetIds: ['11111111-1111-4111-8111-111111111111'],
      }),
    ).rejects.toThrow('cannot be forwarded through the inherited target save');
    expect(fakeHttp.request).not.toHaveBeenCalled();
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

  test('should reject target clone without native API and never request GMP', async () => {
    const fakeHttp = createHttp(createActionResultResponse());
    const cmd = new TargetCommand(fakeHttp);

    await expect(cmd.clone({id: 'target-id'})).rejects.toThrow(
      'Native target API is required for target command',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
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

  test('should create bounded include and exclude host files through native API', async () => {
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
    const file = {
      size: 32,
      text: testing.fn().mockResolvedValue('192.0.2.1\n192.0.2.0/30\n'),
    } as unknown as File;
    const excludeFile = {
      size: 12,
      text: testing.fn().mockResolvedValue('192.0.2.2\n'),
    } as unknown as File;
    const cmd = new TargetCommand(fakeHttp);

    await cmd.create({
      allowSimultaneousIPs: true,
      name: 'File Target',
      comment: 'comment',
      targetSource: 'file',
      targetExcludeSource: 'file',
      file,
      excludeFile,
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

    expect(file.text).toHaveBeenCalledOnce();
    expect(excludeFile.text).toHaveBeenCalledOnce();
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/targets',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          name: 'File Target',
          comment: 'comment',
          port_list_id: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
          hosts: ['192.0.2.1', '192.0.2.0/30'],
          exclude_hosts: ['192.0.2.2'],
          alive_tests: [SCAN_CONFIG_DEFAULT],
          allow_simultaneous_ips: true,
          reverse_lookup_only: false,
          reverse_lookup_unify: true,
        }),
      }),
    );
  });

  test('should save bounded host files through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'target-id'}),
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
    const file = {
      size: 24,
      text: testing.fn().mockResolvedValue('192.0.2.1\n192.0.2.0/30\n'),
    } as unknown as File;
    const cmd = new TargetCommand(fakeHttp);

    await cmd.save({
      id: 'target-id',
      name: 'File Target',
      targetSource: 'file',
      targetExcludeSource: 'manual',
      file,
      excludeHosts: '',
      reverseLookupOnly: false,
      reverseLookupUnify: false,
      portListId: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
      aliveTests: [SCAN_CONFIG_DEFAULT],
      allowSimultaneousIPs: true,
      port: 22,
      sshCredentialId: UNSET_VALUE,
      sshElevateCredentialId: UNSET_VALUE,
      smbCredentialId: UNSET_VALUE,
      esxiCredentialId: UNSET_VALUE,
      snmpCredentialId: UNSET_VALUE,
      krb5CredentialId: UNSET_VALUE,
    });

    expect(file.text).toHaveBeenCalledOnce();
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/targets/target-id',
      expect.objectContaining({
        method: 'PATCH',
        body: JSON.stringify({
          name: 'File Target',
          alive_tests: [SCAN_CONFIG_DEFAULT],
          allow_simultaneous_ips: true,
          reverse_lookup_only: false,
          reverse_lookup_unify: false,
          port_list_id: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
          hosts: ['192.0.2.1', '192.0.2.0/30'],
          exclude_hosts: [],
          credentials: {
            ssh: null,
            ssh_elevate: null,
            smb: null,
            esxi: null,
            snmp: null,
            krb5: null,
          },
        }),
      }),
    );
  });

  test('should reject when a bounded host file cannot be read', async () => {
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
    const file = {
      size: 16,
      text: testing.fn().mockRejectedValue(new Error('read failed')),
    } as unknown as File;
    const cmd = new TargetCommand(fakeHttp);

    await expect(
      cmd.create({
        allowSimultaneousIPs: true,
        name: 'Unreadable File Target',
        targetSource: 'file',
        targetExcludeSource: 'manual',
        file,
        excludeHosts: '',
        reverseLookupOnly: false,
        reverseLookupUnify: false,
        portListId: 'pl-id',
        aliveTests: [SCAN_CONFIG_DEFAULT],
        port: 22,
      }),
    ).rejects.toThrow('Native target source preparation failed');

    expect(file.text).toHaveBeenCalledOnce();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject oversized host files without a legacy upload', async () => {
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
    const file = {
      size: 256 * 1024 + 1,
      text: testing.fn(),
    } as unknown as File;
    const cmd = new TargetCommand(fakeHttp);

    await expect(
      cmd.create({
        allowSimultaneousIPs: true,
        name: 'Large File Target',
        targetSource: 'file',
        targetExcludeSource: 'manual',
        file,
        excludeHosts: '',
        reverseLookupOnly: false,
        reverseLookupUnify: false,
        portListId: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
        aliveTests: [SCAN_CONFIG_DEFAULT],
        port: 22,
        sshCredentialId: UNSET_VALUE,
        sshElevateCredentialId: UNSET_VALUE,
        smbCredentialId: UNSET_VALUE,
        esxiCredentialId: UNSET_VALUE,
        snmpCredentialId: UNSET_VALUE,
        krb5CredentialId: UNSET_VALUE,
      }),
    ).rejects.toThrow('Native target source preparation failed');

    expect(file.text).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject when encoded JSON exceeds the native body limit', async () => {
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
    const text = Array.from(
      {length: 70},
      (_, index) => `${'"'.repeat(3500)}${index}`,
    ).join('\n');
    const file = {
      size: new TextEncoder().encode(text).byteLength,
      text: testing.fn().mockResolvedValue(text),
    } as unknown as File;
    const cmd = new TargetCommand(fakeHttp);

    await expect(
      cmd.create({
        allowSimultaneousIPs: true,
        name: 'Encoded Large File Target',
        targetSource: 'file',
        targetExcludeSource: 'manual',
        file,
        excludeHosts: '',
        reverseLookupOnly: false,
        reverseLookupUnify: false,
        portListId: 'pl-id',
        aliveTests: [SCAN_CONFIG_DEFAULT],
        port: 22,
      }),
    ).rejects.toThrow(
      'Native target request exceeds the native request-size limit',
    );

    expect(file.size).toBeLessThan(256 * 1024);
    expect(file.text).toHaveBeenCalledOnce();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject an inconsistent file shape without legacy fallback', async () => {
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
        allowSimultaneousIPs: true,
        name: 'Inherited Target',
        targetSource: 'file',
        targetExcludeSource: 'manual',
        hosts: '',
        excludeHosts: '',
        reverseLookupOnly: false,
        reverseLookupUnify: false,
        portListId: 'pl-id',
        aliveTests: [SCAN_CONFIG_DEFAULT],
        port: 22,
      }),
    ).rejects.toThrow('Native target source preparation failed');

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
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

  test('should refuse target deletion locally when native API is unavailable', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(createActionResultResponse());
    const cmd = new TargetCommand(fakeHttp);

    await expect(cmd.delete({id: 'target-id'})).rejects.toThrow(
      'Native target API is required for target command',
    );
    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
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

  test('should create a target from host asset IDs only through native API', async () => {
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
    const hostAssetIds = [
      '11111111-1111-4111-8111-111111111111',
      '22222222-2222-4222-8222-222222222222',
    ];

    await cmd.create({
      allowSimultaneousIPs: true,
      name: 'Asset Target',
      targetSource: 'asset_hosts',
      targetExcludeSource: 'manual',
      hostAssetIds,
      excludeHosts: '',
      reverseLookupOnly: false,
      reverseLookupUnify: false,
      portListId: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
      aliveTests: [SCAN_CONFIG_DEFAULT],
      port: 22,
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/targets',
      expect.objectContaining({
        body: JSON.stringify({
          name: 'Asset Target',
          comment: '',
          port_list_id: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
          host_asset_ids: hostAssetIds,
          exclude_hosts: [],
          alive_tests: [SCAN_CONFIG_DEFAULT],
          allow_simultaneous_ips: true,
          reverse_lookup_only: false,
          reverse_lookup_unify: false,
        }),
      }),
    );
  });

  test.each([
    {name: 'empty', hostAssetIds: []},
    {
      name: 'duplicate',
      hostAssetIds: [
        '11111111-1111-4111-8111-111111111111',
        '11111111-1111-4111-8111-111111111111',
      ],
    },
  ])(
    'should reject $name host asset IDs without GMP fallback',
    async ({hostAssetIds}) => {
      const fetchMock = testing.fn();
      testing.stubGlobal('fetch', fetchMock);
      const fakeHttp = createHttp(undefined) as ReturnType<
        typeof createHttp
      > & {
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
          allowSimultaneousIPs: true,
          name: 'Asset Target',
          targetSource: 'asset_hosts',
          targetExcludeSource: 'manual',
          hostAssetIds,
          excludeHosts: '',
          reverseLookupOnly: false,
          reverseLookupUnify: false,
          portListId: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
          aliveTests: [SCAN_CONFIG_DEFAULT],
          port: 22,
        }),
      ).rejects.toThrow(
        'Host-asset target creation requires the native asset_hosts source and 1 to 4095 unique host asset IDs',
      );
      expect(fetchMock).not.toHaveBeenCalled();
      expect(fakeHttp.request).not.toHaveBeenCalled();
    },
  );

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

  test('should reject invalid credential target creates without GMP fallback', async () => {
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

    await expect(
      cmd.create({
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
      }),
    ).rejects.toThrow('Native target request conversion failed');

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should create bounded manual host expressions through native API', async () => {
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
      hosts:
        '192.0.2.0/24,\n010.000.000.001, 192.0.2.1-192.0.2.3, 2001:db8::/126, 2001:db8::1-2001:db8::3',
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
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/targets',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          name: 'name',
          comment: 'comment',
          port_list_id: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
          hosts: [
            '192.0.2.0/24',
            '010.000.000.001',
            '192.0.2.1-192.0.2.3',
            '2001:db8::/126',
            '2001:db8::1-2001:db8::3',
          ],
          exclude_hosts: [],
          alive_tests: [SCAN_CONFIG_DEFAULT],
          allow_simultaneous_ips: true,
          reverse_lookup_only: false,
          reverse_lookup_unify: true,
        }),
      }),
    );
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

  test('should route exact full exclusion to native validation instead of GMP', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: false,
      status: 400,
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

    await expect(
      cmd.save({
        id: 'target_id1',
        allowSimultaneousIPs: true,
        name: 'name',
        comment: 'comment',
        targetSource: 'manual',
        targetExcludeSource: 'manual',
        hosts: '192.0.2.0/24',
        excludeHosts: '192.0.2.0/24',
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
      }),
    ).rejects.toThrow('Native API request failed with status 400');

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/targets/target_id1',
      expect.objectContaining({
        method: 'PATCH',
        body: JSON.stringify({
          name: 'name',
          comment: 'comment',
          alive_tests: [SCAN_CONFIG_DEFAULT],
          allow_simultaneous_ips: true,
          reverse_lookup_only: false,
          reverse_lookup_unify: true,
          port_list_id: '4f9d2c83-345f-4a91-9d2c-83345f0a9123',
          hosts: ['192.0.2.0/24'],
          exclude_hosts: ['192.0.2.0/24'],
          credentials: {
            ssh: null,
            ssh_elevate: null,
            smb: null,
            esxi: null,
            snmp: null,
            krb5: null,
          },
        }),
      }),
    );
  });
});
