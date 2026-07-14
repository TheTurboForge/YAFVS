/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import CredentialCommand from 'gmp/commands/credential';
import {createHttp, createActionResultResponse} from 'gmp/commands/testing';
import {createSession} from 'gmp/testing';
import {
  CERTIFICATE_CREDENTIAL_TYPE,
  KRB5_CREDENTIAL_TYPE,
} from 'gmp/models/credential';

const certificate = new File(['cert'], 'cert.pem');
const privateKey = new File(['private_key'], 'key.pem');
const publicKey = new File(['public_key'], 'key.pub');

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('CredentialCommand tests', () => {
  test('should export redacted credential metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'credential-id',
        name: 'SSH credential',
        credential_type: 'usk',
        targets: [{id: 'target-id', name: 'Target', use_type: 'scan'}],
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
    const cmd = new CredentialCommand(fakeHttp);

    const result = await cmd.export({id: 'credential-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/credentials/credential-id/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/credentials/credential-id/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: 'credential-id',
      name: 'SSH credential',
      credential_type: 'usk',
      targets: [{id: 'target-id', name: 'Target', use_type: 'scan'}],
    });
  });

  test('should create KRB5 credential with empty kdcs', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new CredentialCommand(fakeHttp);

    const resp = await cmd.createKrb5({
      name: 'krb5-empty-kdcs',
      comment: 'KRB5 credential with empty kdcs',
      credentialType: KRB5_CREDENTIAL_TYPE,
      credentialLogin: 'krb5user',
      password: 'krb5password',
      realm: 'EXAMPLE.COM',
      kdcs: [], // Empty array
    });

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'create_credential',
        auth_algorithm: undefined,
        autogenerate: 0,
        certificate: undefined,
        comment: 'KRB5 credential with empty kdcs',
        community: undefined,
        credential_login: 'krb5user',
        credential_type: KRB5_CREDENTIAL_TYPE,
        lsc_password: 'krb5password',
        name: 'krb5-empty-kdcs',
        passphrase: undefined,
        privacy_algorithm: undefined,
        privacy_password: undefined,
        private_key: undefined,
        public_key: undefined,
        realm: 'EXAMPLE.COM',
        'kdcs:': '', // Should be empty string when kdcs is empty array
      },
    });

    expect(resp.data.id).toEqual('foo');
  });




  test('should create credential', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new CredentialCommand(fakeHttp);
    const resp = await cmd.create({name: 'test-credential'});

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'create_credential',
        name: 'test-credential',
        comment: undefined,
        autogenerate: 0,
        community: undefined,
        credential_login: undefined,
        lsc_password: undefined,
        passphrase: undefined,
        privacy_password: undefined,
        auth_algorithm: undefined,
        privacy_algorithm: undefined,
        private_key: undefined,
        public_key: undefined,
        certificate: undefined,
        credential_type: undefined,
      },
    });

    const {data} = resp;
    expect(data.id).toEqual('foo');
  });

  test('should create credential with all params', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);

    const cmd = new CredentialCommand(fakeHttp);
    const resp = await cmd.create({
      name: 'full-credential',
      comment: 'a full credential',
      authAlgorithm: 'md5',
      autogenerate: true,
      certificate,
      community: 'community',
      credentialLogin: 'login',
      credentialType: CERTIFICATE_CREDENTIAL_TYPE,
      password: 'password',
      passphrase: 'passphrase',
      privacyAlgorithm: 'des',
      privacyPassword: 'privacy_password',
      privateKey,
      publicKey,
    });

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'create_credential',
        name: 'full-credential',
        comment: 'a full credential',
        auth_algorithm: 'md5',
        autogenerate: 1,
        certificate,
        community: 'community',
        credential_login: 'login',
        credential_type: CERTIFICATE_CREDENTIAL_TYPE,
        lsc_password: 'password',
        passphrase: 'passphrase',
        privacy_algorithm: 'des',
        privacy_password: 'privacy_password',
        private_key: privateKey,
        public_key: publicKey,
      },
    });
    expect(resp.data.id).toEqual('foo');
  });


  test('should create regular KRB5 credential with KDC validation', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new CredentialCommand(fakeHttp);

    const resp = await cmd.createKrb5({
      name: 'krb5-regular-credential',
      comment: 'Regular KRB5 credential',
      credentialType: KRB5_CREDENTIAL_TYPE,
      credentialLogin: 'krb5user',
      password: 'krb5password',
      realm: 'EXAMPLE.COM',
      kdcs: ['kdc1.example.com', 'kdc2.example.com'],
    });

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'create_credential',
        autogenerate: 0,
        certificate: undefined,
        comment: 'Regular KRB5 credential',
        community: undefined,
        credential_login: 'krb5user',
        credential_type: KRB5_CREDENTIAL_TYPE,
        lsc_password: 'krb5password',
        name: 'krb5-regular-credential',
        passphrase: undefined,
        private_key: undefined,
        public_key: undefined,
        realm: 'EXAMPLE.COM',
        'kdcs:': ['kdc1.example.com', 'kdc2.example.com'],
        auth_algorithm: undefined,
        privacy_algorithm: undefined,
        privacy_password: undefined,
      },
    });

    expect(resp.data.id).toEqual('foo');
  });


  test('should save credential with minimal params', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);

    const cmd = new CredentialCommand(fakeHttp);
    const resp = await cmd.save({
      id: '1',
      name: 'updated-credential',
    });

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_credential',
        credential_id: '1',
        name: 'updated-credential',
        comment: undefined,
        auth_algorithm: undefined,
        certificate: undefined,
        community: undefined,
        credential_login: undefined,
        credential_type: undefined,
        passphrase: undefined,
        password: undefined,
        privacy_algorithm: undefined,
        privacy_password: undefined,
        private_key: undefined,
        public_key: undefined,
      },
    });
    expect(resp.data.id).toEqual('foo');
  });

  test('should save credential metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: '1', name: 'updated-credential'}),
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

    const cmd = new CredentialCommand(fakeHttp);
    const resp = await cmd.save({
      id: '1',
      name: 'updated-credential',
      comment: 'metadata only',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/credentials/1');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/credentials/1',
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
          name: 'updated-credential',
          comment: 'metadata only',
        }),
      },
    );
    expect(resp.data.id).toEqual('1');
  });

  test('should keep secret-bearing credential save on GMP', async () => {
    const response = createActionResultResponse();
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

    const cmd = new CredentialCommand(fakeHttp);
    const resp = await cmd.save({
      id: '1',
      name: 'updated-credential',
      password: 'secret-password',
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: expect.objectContaining({
        cmd: 'save_credential',
        credential_id: '1',
        name: 'updated-credential',
        password: 'secret-password',
      }),
    });
    expect(resp.data.id).toEqual('foo');
  });

  test('should save credential with all params', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);

    const cmd = new CredentialCommand(fakeHttp);
    const resp = await cmd.save({
      id: '1',
      name: 'updated-credential',
      comment: 'updated comment',
      authAlgorithm: 'md5',
      certificate,
      community: 'community',
      credentialLogin: 'login',
      credentialType: 'cc',
      passphrase: 'passphrase',
      password: 'password',
      privacyAlgorithm: 'des',
      privacyPassword: 'privacy_password',
      privateKey,
      publicKey,
    });

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_credential',
        credential_id: '1',
        name: 'updated-credential',
        comment: 'updated comment',
        auth_algorithm: 'md5',
        certificate,
        community: 'community',
        credential_login: 'login',
        credential_type: CERTIFICATE_CREDENTIAL_TYPE,
        passphrase: 'passphrase',
        password: 'password',
        privacy_algorithm: 'des',
        privacy_password: 'privacy_password',
        private_key: privateKey,
        public_key: publicKey,
      },
    });
    expect(resp.data.id).toEqual('foo');
  });

  test('should keep files when saving credential', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);

    const cmd = new CredentialCommand(fakeHttp);
    const resp = await cmd.save({
      id: '2',
      name: 'keep-files-credential',
      certificate: new File([], 'empty.pem'),
      privateKey: new File([], 'empty.key'),
      publicKey: new File([], 'empty.pub'),
    });

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_credential',
        auth_algorithm: undefined,
        certificate: undefined,
        comment: undefined,
        community: undefined,
        credential_id: '2',
        credential_login: undefined,
        credential_type: undefined,
        name: 'keep-files-credential',
        passphrase: undefined,
        password: undefined,
        privacy_algorithm: undefined,
        privacy_password: undefined,
        private_key: undefined,
        public_key: undefined,
      },
    });
    expect(resp.data.id).toEqual('foo');
  });

  test('should remove files when saving credential', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);

    const cmd = new CredentialCommand(fakeHttp);
    const resp = await cmd.save({
      id: '2',
      name: 'remove-files-credential',
      certificate: null,
      privateKey: null,
      publicKey: null,
    });

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_credential',
        auth_algorithm: undefined,
        certificate: '',
        comment: undefined,
        community: undefined,
        credential_id: '2',
        credential_login: undefined,
        credential_type: undefined,
        name: 'remove-files-credential',
        passphrase: undefined,
        password: undefined,
        privacy_algorithm: undefined,
        privacy_password: undefined,
        private_key: '',
        public_key: '',
      },
    });
    expect(resp.data.id).toEqual('foo');
  });


  test('should save regular KRB5 credential with KDC validation', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new CredentialCommand(fakeHttp);

    const resp = await cmd.saveKrb5({
      id: 'krb5-regular-id',
      name: 'updated-krb5-regular-credential',
      comment: 'Updated regular KRB5 credential',
      credentialType: KRB5_CREDENTIAL_TYPE,
      credentialLogin: 'updated-krb5user',
      password: 'updated-password',
      realm: 'UPDATED.COM',
      kdcs: ['new-kdc.example.com'],
    });

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_credential',
        certificate: undefined,
        comment: 'Updated regular KRB5 credential',
        community: undefined,
        credential_login: 'updated-krb5user',
        credential_type: KRB5_CREDENTIAL_TYPE,
        credential_id: 'krb5-regular-id',
        password: 'updated-password',
        name: 'updated-krb5-regular-credential',
        passphrase: undefined,
        private_key: undefined,
        public_key: undefined,
        realm: 'UPDATED.COM',
        'kdcs:': ['new-kdc.example.com'],
        auth_algorithm: undefined,
        privacy_algorithm: undefined,
        privacy_password: undefined,
      },
    });

    expect(resp.data.id).toEqual('foo');
  });


  test('should download credential', async () => {
    const response = new ArrayBuffer(8);
    const fakeHttp = createHttp(response);

    const cmd = new CredentialCommand(fakeHttp);
    const resp = await cmd.download({id: '1'}, 'pem');

    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'download_credential',
        package_format: 'pem',
        credential_id: '1',
      },
      responseType: 'arraybuffer',
    });

    expect(resp).toEqual(response);
  });

  test('should get element from root', () => {
    const fakeHttp = createHttp();
    const root = {
      get_credential: {
        get_credentials_response: {
          credential: {id: '1', name: 'test-credential'},
        },
      },
    };

    const cmd = new CredentialCommand(fakeHttp);
    const element = cmd.getElementFromRoot(root);

    expect(element).toEqual({id: '1', name: 'test-credential'});
  });

  test('should test createBase helper function through create method', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new CredentialCommand(fakeHttp);

    // Test createBase through regular create function
    await cmd.create({
      name: 'base-test',
      comment: 'Testing base functionality',
      autogenerate: false,
      credentialType: CERTIFICATE_CREDENTIAL_TYPE,
      credentialLogin: 'testuser',
      password: 'testpass',
    });

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'create_credential',
        auth_algorithm: undefined,
        autogenerate: 0,
        certificate: undefined,
        comment: 'Testing base functionality',
        community: undefined,
        credential_login: 'testuser',
        credential_type: CERTIFICATE_CREDENTIAL_TYPE,
        lsc_password: 'testpass',
        name: 'base-test',
        passphrase: undefined,
        privacy_algorithm: undefined,
        privacy_password: undefined,
        private_key: undefined,
        public_key: undefined,
      },
    });
  });

  test('should test saveBase helper function through save method', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new CredentialCommand(fakeHttp);

    // Test saveBase through regular save function
    await cmd.save({
      id: 'test-id',
      name: 'base-save-test',
      comment: 'Testing save base functionality',
      credentialType: CERTIFICATE_CREDENTIAL_TYPE,
      credentialLogin: 'saveuser',
      password: 'savepass',
    });

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_credential',
        credential_id: 'test-id',
        name: 'base-save-test',
        comment: 'Testing save base functionality',
        auth_algorithm: undefined,
        certificate: undefined,
        community: undefined,
        credential_login: 'saveuser',
        credential_type: CERTIFICATE_CREDENTIAL_TYPE,
        passphrase: undefined,
        password: 'savepass',
        privacy_algorithm: undefined,
        privacy_password: undefined,
        private_key: undefined,
        public_key: undefined,
      },
    });
  });
});
