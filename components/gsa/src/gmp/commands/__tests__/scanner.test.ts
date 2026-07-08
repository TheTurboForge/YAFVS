/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import ScannerCommand from 'gmp/commands/scanner';
import {
  createHttp,
  createActionResultResponse,
  createEntityResponse,
  createPlainResponse,
} from 'gmp/commands/testing';
import Scanner, {OPENVASD_SCANNER_TYPE} from 'gmp/models/scanner';
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

describe('ScannerCommand tests', () => {
  test('should export scanner metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: '123',
        name: 'OpenVAS Default',
        host: 'localhost',
        port: 9390,
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new ScannerCommand(fakeHttp);
    const result = await cmd.export({id: '123'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/scanners/123/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scanners/123/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: '123',
      name: 'OpenVAS Default',
      host: 'localhost',
      port: 9390,
    });
  });

  test('should send the correct data to create a scanner', async () => {
    const response = createActionResultResponse({
      action: 'create_scanner',
      id: '123',
      message: 'Scanner created successfully',
    });
    const fakeHttp = createHttp(response);
    const cmd = new ScannerCommand(fakeHttp);
    const result = await cmd.create({
      name: 'Test Scanner',
      host: '127.0.0.1',
      port: 9390,
      type: OPENVASD_SCANNER_TYPE,
      comment: 'Test comment',
      caCertificate: 'test-ca-pub' as unknown as File,
      credentialId: 'test-credential-id',
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'create_scanner',
        name: 'Test Scanner',
        comment: 'Test comment',
        credential_id: 'test-credential-id',
        scanner_host: '127.0.0.1',
        scanner_type: OPENVASD_SCANNER_TYPE,
        port: 9390,
        ca_pub: 'test-ca-pub',
      },
    });
    expect(result.data.id).toEqual('123');
  });

  test('should save a scanner', async () => {
    const response = createActionResultResponse({
      action: 'save_scanner',
      id: '123',
      message: 'Scanner updated successfully',
    });
    const fakeHttp = createHttp(response);
    const cmd = new ScannerCommand(fakeHttp);
    await cmd.save({
      id: '123',
      name: 'Updated Scanner',
      host: '127.0.0.1',
      port: 9390,
      type: OPENVASD_SCANNER_TYPE,
      comment: 'Updated comment',
      caCertificate: 'updated-ca-pub' as unknown as File,
      credentialId: 'updated-credential-id',
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_scanner',
        scanner_id: '123',
        name: 'Updated Scanner',
        comment: 'Updated comment',
        credential_id: 'updated-credential-id',
        scanner_host: '127.0.0.1',
        scanner_type: OPENVASD_SCANNER_TYPE,
        port: 9390,
        ca_pub: 'updated-ca-pub',
      },
    });
  });

  test('should save scanner metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: '123', name: 'Updated Scanner'}),
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

    const cmd = new ScannerCommand(fakeHttp);
    const result = await cmd.save({
      id: '123',
      name: 'Updated Scanner',
      comment: 'metadata only',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/scanners/123');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scanners/123',
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
          name: 'Updated Scanner',
          comment: 'metadata only',
        }),
      },
    );
    expect(result.data.id).toEqual('123');
  });

  test('should keep scanner control saves on GMP when native API is available', async () => {
    const response = createActionResultResponse({
      action: 'save_scanner',
      id: '123',
      message: 'Scanner updated successfully',
    });
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

    const cmd = new ScannerCommand(fakeHttp);
    await cmd.save({
      id: '123',
      name: 'Updated Scanner',
      host: '127.0.0.1',
      port: 9390,
      type: OPENVASD_SCANNER_TYPE,
      comment: 'Updated comment',
      caCertificate: 'updated-ca-pub' as unknown as File,
      credentialId: 'updated-credential-id',
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_scanner',
        scanner_id: '123',
        name: 'Updated Scanner',
        comment: 'Updated comment',
        credential_id: 'updated-credential-id',
        scanner_host: '127.0.0.1',
        scanner_type: OPENVASD_SCANNER_TYPE,
        port: 9390,
        ca_pub: 'updated-ca-pub',
      },
    });
  });

  test('should remove a credential when saving a scanner', async () => {
    const response = createActionResultResponse({
      action: 'save_scanner',
      id: '123',
      message: 'Scanner updated successfully',
    });
    const fakeHttp = createHttp(response);
    const cmd = new ScannerCommand(fakeHttp);
    await cmd.save({
      id: '123',
      name: 'Updated Scanner',
      host: '127.0.0.1',
      port: 9390,
      type: OPENVASD_SCANNER_TYPE,
      comment: 'Updated comment',
      caCertificate: 'updated-ca-pub' as unknown as File,
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_scanner',
        ca_pub: 'updated-ca-pub',
        credential_id: '',
        scanner_id: '123',
        name: 'Updated Scanner',
        comment: 'Updated comment',
        scanner_host: '127.0.0.1',
        scanner_type: OPENVASD_SCANNER_TYPE,
        port: 9390,
      },
    });
  });

  test('should remove ca cert when saving a scanner', async () => {
    const response = createActionResultResponse({
      action: 'save_scanner',
      id: '123',
      message: 'Scanner updated successfully',
    });
    const fakeHttp = createHttp(response);
    const cmd = new ScannerCommand(fakeHttp);
    await cmd.save({
      id: '123',
      name: 'Updated Scanner',
      host: '127.0.0.1',
      port: 9390,
      type: OPENVASD_SCANNER_TYPE,
      comment: 'Updated comment',
      credentialId: '123',
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_scanner',
        ca_pub: '',
        credential_id: '123',
        scanner_id: '123',
        name: 'Updated Scanner',
        comment: 'Updated comment',
        scanner_host: '127.0.0.1',
        scanner_type: OPENVASD_SCANNER_TYPE,
        port: 9390,
      },
    });
  });

  test('should send the correct data to verify a scanner', async () => {
    const response = createActionResultResponse({
      action: 'verify_scanner',
      id: '123',
      message: 'OK',
    });
    const fakeHttp = createHttp(response);
    const cmd = new ScannerCommand(fakeHttp);
    await cmd.verify({id: '123'});
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'verify_scanner',
        scanner_id: '123',
      },
    });
  });

  test('should fetch scanner detail through native API without details by default', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: '123',
        name: 'Test Scanner',
        scanner_type: Number(OPENVASD_SCANNER_TYPE),
        host: '127.0.0.1',
        port: 9390,
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScannerCommand(fakeHttp);
    const result = await cmd.get({id: '123'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/scanners/123', {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scanners/123',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data.id).toEqual('123');
    expect(result.data.name).toEqual('Test Scanner');
    expect(result.data.host).toEqual('127.0.0.1');
    expect(result.data.port).toEqual(9390);
    expect(result.data.scannerType).toEqual(OPENVASD_SCANNER_TYPE);
  });

  test('should keep filtered scanner detail on GMP until native parity is characterized', async () => {
    const response = createEntityResponse('scanner', {
      id: '123',
      name: 'Test Scanner',
      type: OPENVASD_SCANNER_TYPE,
    });
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
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new ScannerCommand(fakeHttp);
    const result = await cmd.get({id: '123'}, {filter: 'tasks=1'});

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_scanner',
        scanner_id: '123',
        filter: 'tasks=1',
        details: '0',
      },
    });
    expect(result.data.id).toEqual('123');
    expect(result.data.name).toEqual('Test Scanner');
    expect(result.data.scannerType).toEqual(OPENVASD_SCANNER_TYPE);
  });

  test('should keep scanner detail with details on GMP when requested', async () => {
    const response = createEntityResponse('scanner', {
      id: '123',
      name: 'Test Scanner',
      type: OPENVASD_SCANNER_TYPE,
    });
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    fakeHttp.request = testing.fn().mockResolvedValue(response);
    const cmd = new ScannerCommand(fakeHttp);
    const result = await cmd.get({id: '123'}, {details: true});
    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_scanner',
        scanner_id: '123',
        details: '1',
      },
    });
    expect(result.data.id).toEqual('123');
    expect(result.data.name).toEqual('Test Scanner');
    expect(result.data.scannerType).toEqual(OPENVASD_SCANNER_TYPE);
  });

  test('should fetch scanner detail through native API with details explicitly false', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: '123',
        name: 'Test Scanner',
        scanner_type: Number(OPENVASD_SCANNER_TYPE),
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScannerCommand(fakeHttp);
    const result = await cmd.get({id: '123'}, {details: false});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/scanners/123', {
      token: 'test-token',
    });
    expect(result.data.id).toEqual('123');
    expect(result.data.name).toEqual('Test Scanner');
    expect(result.data.scannerType).toEqual(OPENVASD_SCANNER_TYPE);
  });

  test('should keep explicit no-detail scanner fallback on GMP when native API is not available', async () => {
    const response = createEntityResponse('scanner', {
      id: '123',
      name: 'Test Scanner',
      type: OPENVASD_SCANNER_TYPE,
    });
    const fakeHttp = createHttp(response);
    const cmd = new ScannerCommand(fakeHttp);
    const result = await cmd.get({id: '123'}, {details: false});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_scanner',
        scanner_id: '123',
        details: '0',
      },
    });
    expect(result.data).toEqual(
      new Scanner({
        id: '123',
        name: 'Test Scanner',
        scannerType: OPENVASD_SCANNER_TYPE,
      }),
    );
  });

});
