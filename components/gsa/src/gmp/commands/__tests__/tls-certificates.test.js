/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {createHttp} from 'gmp/commands/testing';
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
  fakeHttp.buildUrl = testing.fn(path => `https://yafvs.example/${path}`);
  fakeHttp.session = createSession();
  fakeHttp.session.token = 'test-token';
  fakeHttp.session.jwt = 'jwt-token';
  return fakeHttp;
};

describe('TlsCertificateCommand tests', () => {
  test('should require native API for TLS certificate PEM data', async () => {
    const fakeHttp = createHttp(undefined);
    const cmd = new TlsCertificateCommand(fakeHttp);

    await expect(cmd.get({id: 'foo'})).rejects.toThrow(
      'Native TLS certificate API is required for this operation',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should require native API for TLS certificate deletion', async () => {
    const fakeHttp = createHttp(undefined);
    const cmd = new TlsCertificateCommand(fakeHttp);

    await expect(cmd.delete({id: 'foo'})).rejects.toThrow(
      'Native TLS certificate API is required for this operation',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
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
      'https://yafvs.example/api/v1/tls-certificates/tls-certificate-id',
      {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
          'X-YAFVS-Token': 'test-token',
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
      'https://yafvs.example/api/v1/tls-certificates/tls-certificate-id/export',
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
      'https://yafvs.example/api/v1/tls-certificates/tls-certificate-id/certificate',
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
  test('should require native API for bulk TLS certificate deletion', async () => {
    const fakeHttp = createHttp(undefined);
    const cmd = new TlsCertificatesCommand(fakeHttp);

    await expect(cmd.deleteByIds(['tls-1'])).rejects.toThrow(
      'Native TLS certificate API is required for this operation',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should preflight and bulk delete TLS certificates through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          id: 'tls-1',
          name: 'one',
          writable: true,
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          id: 'tls-2',
          name: 'two',
          writable: true,
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValue({ok: true, status: 204});
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TlsCertificatesCommand(fakeHttp);

    const result = await cmd.deleteByIds(['tls-1', 'tls-2']);

    expect(result.data).toEqual(['tls-1', 'tls-2']);
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(fetchMock.mock.calls[2][1].method).toEqual('DELETE');
    expect(fetchMock.mock.calls[3][1].method).toEqual('DELETE');
  });

  test('should report committed progress when bulk deletion stops', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          id: 'tls-1',
          name: 'one',
          writable: true,
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          id: 'tls-2',
          name: 'two',
          writable: true,
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({ok: true, status: 204})
      .mockResolvedValueOnce({ok: false, status: 409});
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TlsCertificatesCommand(fakeHttp);

    await expect(cmd.deleteByIds(['tls-1', 'tls-2'])).rejects.toThrow(
      'Native TLS certificate bulk delete stopped after 1 of 2 items: Native API request failed with status 409',
    );
    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject a protected TLS certificate before bulk deletion', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'ownerless',
        name: 'protected',
        writable: false,
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TlsCertificatesCommand(fakeHttp);

    await expect(cmd.deleteByIds(['ownerless'])).rejects.toThrow(
      'Native TLS certificate bulk delete includes a protected certificate',
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][1].method).toBeUndefined();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should fetch TLS certificates through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 25,
          total: 1,
          sort: 'name',
          filter: 'example',
        },
        items: [
          {
            id: 'tls-certificate-id',
            name: 'example.org:443',
            subject_dn: 'CN=example.org',
            issuer_dn: 'CN=Example CA',
            writable: true,
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
    expect(result.data[0].isWritable()).toBe(true);
    expect(result.data[0].userCapabilities.mayDelete('tlscertificate')).toBe(
      true,
    );
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
          page: {
            page: 2,
            page_size: 1,
            total: 3,
            sort: 'name',
            filter: 'example',
          },
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
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'name',
            filter: 'example',
          },
          items: [{id: 'tls-1', name: 'one'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 2,
            page_size: 500,
            total: 2,
            sort: 'name',
            filter: 'example',
          },
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
