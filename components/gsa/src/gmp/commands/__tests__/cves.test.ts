/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import CvesCommand from 'gmp/commands/cves';
import {createAggregatesResponse, createHttp} from 'gmp/commands/testing';
import Filter from 'gmp/models/filter';
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

describe('CvesCommand tests', () => {
  test('should fetch cves through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: '-severity', filter: 'Admin'},
        items: [
          {
            id: 'CVE-2026-10001',
            name: 'CVE-2026-10001',
            description: 'Native CVE metadata.',
            cvss_base_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            severity: 9.8,
            products: ['cpe:/a:admin:admin:1.0'],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new CvesCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=Admin'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('CVE-2026-10001');
    expect(result.data[0].severity).toEqual(9.8);
    expect(result.data[0].products).toEqual(['cpe:/a:admin:admin:1.0']);
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/cves', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'severity',
      filter: 'Admin',
    });
  });

  test('should page through native API for getAll', async () => {
    const responses = [
      {
        page: {page: 1, page_size: 2, total: 3, sort: '-severity', filter: ''},
        items: [
          {id: 'CVE-2026-10001', name: 'CVE-2026-10001', severity: 9.8},
          {id: 'CVE-2026-10002', name: 'CVE-2026-10002', severity: 7.5},
        ],
      },
      {
        page: {page: 2, page_size: 2, total: 3, sort: '-severity', filter: ''},
        items: [{id: 'CVE-2026-10003', name: 'CVE-2026-10003', severity: 5.0}],
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

    const cmd = new CvesCommand(fakeHttp);
    const result = await cmd.getAll();

    expect(result.data.map(cve => cve.id)).toEqual([
      'CVE-2026-10001',
      'CVE-2026-10002',
      'CVE-2026-10003',
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  test('should bulk export selected CVEs through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'CVE-2026-10001'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'CVE-2026-10002'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new CvesCommand(fakeHttp);

    const result = await cmd.exportByIds(['CVE-2026-10001', 'CVE-2026-10002']);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/cves/CVE-2026-10001/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).cves).toEqual([
      {id: 'CVE-2026-10001'},
      {id: 'CVE-2026-10002'},
    ]);
  });

  test('should bulk export current page filter through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 1, total: 3, sort: 'severity', filter: 'Admin'},
          items: [{id: 'CVE-2026-10002'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'CVE-2026-10002'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new CvesCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=Admin');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/cves', {
      token: 'test-token',
      page: 2,
      page_size: 1,
      sort: 'severity',
      filter: 'Admin',
    });
    expect(JSON.parse(result.data).cves).toEqual([{id: 'CVE-2026-10002'}]);
  });

  test('should bulk export all filtered CVEs through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 1, page_size: 500, total: 2, sort: 'severity', filter: 'Admin'},
          items: [{id: 'CVE-2026-10001'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 500, total: 2, sort: 'severity', filter: 'Admin'},
          items: [{id: 'CVE-2026-10002'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'CVE-2026-10001'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'CVE-2026-10002'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new CvesCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=Admin').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/cves', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'severity',
      filter: 'Admin',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/cves', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'severity',
      filter: 'Admin',
    });
    expect(JSON.parse(result.data).cves).toEqual([
      {id: 'CVE-2026-10001'},
      {id: 'CVE-2026-10002'},
    ]);
  });


});
