/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {
  createActionResultResponse,
  createEntityResponse,
  createHttp,
} from 'gmp/commands/testing';
import {
  TlsCertificateCommand,
  TlsCertificatesCommand,
} from 'gmp/commands/tls-certificates';
import Filter from 'gmp/models/filter';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

const createNativeHttp = () => {
  const fakeHttp = createHttp(undefined);
  fakeHttp.buildUrl = testing.fn(
    path => `https://turbovas.example/${path}`,
  );
  fakeHttp.session = createSession();
  fakeHttp.session.token = 'test-token';
  fakeHttp.session.jwt = 'jwt-token';
  return fakeHttp;
};

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

  test('should delete a TLS certificate through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: true,
      status: 204,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TlsCertificateCommand(fakeHttp);

    await cmd.delete({id: 'tls-certificate-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/tls-certificates/tls-certificate-id',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tls-certificates/tls-certificate-id',
      {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
          'X-TurboVAS-Token': 'test-token',
        },
      },
    );
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
    const fakeHttp = createNativeHttp();

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

  test('should fetch TLS certificate PEM data through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'tls-certificate-id',
        certificate: 'BASE64CERTIFICATE',
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new TlsCertificateCommand(fakeHttp);
    const result = await cmd.get({id: 'tls-certificate-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/tls-certificates/tls-certificate-id/certificate',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tls-certificates/tls-certificate-id/certificate',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data.id).toEqual('tls-certificate-id');
    expect(result.data.certificate).toEqual('BASE64CERTIFICATE');
  });

});

describe('TlsCertificatesCommand tests', () => {
  test('should fetch TLS certificates through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: 'example'},
        items: [
          {
            id: 'tls-certificate-id',
            name: 'example.org:443',
            subject_dn: 'CN=example.org',
            issuer_dn: 'CN=Example CA',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new TlsCertificatesCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=example'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('tls-certificate-id');
    expect(result.data[0].subjectDn).toEqual('CN=example.org');
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/tls-certificates', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'last_seen',
      filter: 'example',
    });
  });

  test('should page through native API for getAll', async () => {
    const responses = [
      {
        page: {page: 1, page_size: 500, total: 2, sort: 'name', filter: ''},
        items: [{id: 'tls-1', name: 'one'}],
      },
      {
        page: {page: 2, page_size: 500, total: 2, sort: 'name', filter: ''},
        items: [{id: 'tls-2', name: 'two'}],
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

    const cmd = new TlsCertificatesCommand(fakeHttp);
    const result = await cmd.getAll();

    expect(result.data.map(cert => cert.id)).toEqual(['tls-1', 'tls-2']);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  test('should bulk export selected TLS certificates through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'tls-1', name: 'one'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'tls-2', name: 'two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TlsCertificatesCommand(fakeHttp);

    const result = await cmd.exportByIds(['tls-1', 'tls-2']);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/tls-certificates/tls-1/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).tls_certificates).toEqual([
      {id: 'tls-1', name: 'one'},
      {id: 'tls-2', name: 'two'},
    ]);
  });

  test('should bulk export current page filter through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 1, total: 3, sort: 'name', filter: 'example'},
          items: [{id: 'tls-2', name: 'two'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'tls-2', name: 'two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TlsCertificatesCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=example');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/tls-certificates',
      {
        token: 'test-token',
        page: 2,
        page_size: 1,
        sort: 'last_seen',
        filter: 'example',
      },
    );
    expect(JSON.parse(result.data).tls_certificates).toEqual([
      {id: 'tls-2', name: 'two'},
    ]);
  });

  test('should bulk export all filtered TLS certificates through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 1, page_size: 500, total: 2, sort: 'name', filter: 'example'},
          items: [{id: 'tls-1', name: 'one'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 500, total: 2, sort: 'name', filter: 'example'},
          items: [{id: 'tls-2', name: 'two'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'tls-1', name: 'one'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'tls-2', name: 'two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TlsCertificatesCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=example').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/tls-certificates',
      {
        token: 'test-token',
        page: 1,
        page_size: 500,
        sort: 'last_seen',
        filter: 'example',
      },
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/tls-certificates',
      {
        token: 'test-token',
        page: 2,
        page_size: 500,
        sort: 'last_seen',
        filter: 'example',
      },
    );
    expect(JSON.parse(result.data).tls_certificates).toEqual([
      {id: 'tls-1', name: 'one'},
      {id: 'tls-2', name: 'two'},
    ]);
  });
});
