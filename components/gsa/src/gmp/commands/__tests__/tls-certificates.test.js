/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {
  createActionResultResponse,
  createEntitiesResponse,
  createEntityResponse,
  createHttp,
  createPlainResponse,
} from 'gmp/commands/testing';
import {
  TlsCertificateCommand,
  TlsCertificatesCommand,
} from 'gmp/commands/tls-certificates';
import {ALL_FILTER} from 'gmp/models/filter';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('TlsCertificateCommand tests', () => {
  test('should return a single TLS certificate', async () => {
    const response = createEntityResponse('tls_certificate', {
      _id: 'foo',
      certificate: {__text: 'lorem'},
    });
    const fakeHttp = createHttp(response);
    const cmd = new TlsCertificateCommand(fakeHttp);
    const resp = await cmd.get({id: 'foo'});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_tls_certificate',
        tls_certificate_id: 'foo',
      },
    });
    const {data} = resp;
    expect(data.id).toEqual('foo');
  });

  test('should delete a TLS certificate', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new TlsCertificateCommand(fakeHttp);
    await cmd.delete({
      id: 'foo',
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'delete_tls_certificate',
        tls_certificate_id: 'foo',
      },
    });
  });

  test('should export a TLS certificate', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new TlsCertificateCommand(fakeHttp);
    await cmd.export({
      id: 'foo',
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'bulk_export',
        resource_type: 'tls_certificate',
        bulk_select: 1,
        'bulk_selected:foo': 1,
      },
    });
  });

  test('should export TLS certificate metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'tls-certificate-id',
        name: 'example.org:443',
        subject_dn: 'CN=example.org',
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined);
    fakeHttp.buildUrl = testing.fn(
      path => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new TlsCertificateCommand(fakeHttp);
    const result = await cmd.export({id: 'tls-certificate-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/tls-certificates/tls-certificate-id/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tls-certificates/tls-certificate-id/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: 'tls-certificate-id',
      name: 'example.org:443',
      subject_dn: 'CN=example.org',
    });
  });

  test('should fall back to GMP when native TLS certificate metadata export fails', async () => {
    const content = '<some><xml>exported-data</xml></some>';
    const response = createPlainResponse(content);
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'disabled'}}),
      ok: false,
      status: 503,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response);
    fakeHttp.buildUrl = testing.fn(
      path => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new TlsCertificateCommand(fakeHttp);
    const result = await cmd.export({id: 'tls-certificate-id'});

    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'bulk_export',
        resource_type: 'tls_certificate',
        bulk_select: 1,
        'bulk_selected:tls-certificate-id': 1,
      },
    });
    expect(result.data).toEqual(content);
  });
});

describe('TlsCertificatesCommand tests', () => {
  test('should return all TLS certificates', async () => {
    const response = createEntitiesResponse('tls_certificate', [
      {
        _id: '1',
        certificate: {
          __text: 'foo',
        },
      },
      {
        _id: '2',
        certificate: {
          __text: 'bar',
        },
      },
    ]);

    const fakeHttp = createHttp(response);
    const cmd = new TlsCertificatesCommand(fakeHttp);
    const resp = await cmd.getAll();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_tls_certificates',
        filter: ALL_FILTER.toFilterString(),
      },
    });
    const {data} = resp;
    expect(data.length).toEqual(2);
  });

  test('should return TLS certificates', async () => {
    const response = createEntitiesResponse('tls_certificate', [
      {
        _id: '1',
        certificate: {
          __text: 'foo',
        },
      },
      {
        _id: '2',
        certificate: {
          __text: 'foo',
        },
      },
    ]);
    const fakeHttp = createHttp(response);
    const cmd = new TlsCertificatesCommand(fakeHttp);
    const resp = await cmd.get();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_tls_certificates',
      },
    });
    const {data} = resp;
    expect(data.length).toEqual(2);
  });
});
