/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import CvesCommand from 'gmp/commands/cves';
import {
  createAggregatesResponse,
  createHttp,
  createInfoEntitiesResponse,
} from 'gmp/commands/testing';
import Cve from 'gmp/models/cve';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('CvesCommand tests', () => {
  test('should fetch cves with default params', async () => {
    const response = createInfoEntitiesResponse([
      {
        _id: '1',
        name: 'Admin',
        cve: {
          severity: 10.0,
        },
      },
      {
        _id: '2',
        name: 'User',
        cve: {
          severity: 5.0,
        },
      },
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new CvesCommand(fakeHttp);
    const result = await cmd.get();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_info', info_type: 'cve'},
    });
    expect(result.data).toEqual([
      new Cve({
        id: '1',
        name: 'Admin',
        severity: 10.0,
      }),
      new Cve({
        id: '2',
        name: 'User',
        severity: 5.0,
      }),
    ]);
  });

  test('should fetch cves with custom params', async () => {
    const response = createInfoEntitiesResponse([
      {
        _id: '1',
        name: 'Admin',
        cve: {
          severity: 10.0,
        },
      },
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new CvesCommand(fakeHttp);
    const result = await cmd.get({filter: "name='Admin'"});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_info',
        info_type: 'cve',
        filter: "name='Admin'",
      },
    });
    expect(result.data).toEqual([
      new Cve({id: '1', name: 'Admin', severity: 10.0}),
    ]);
  });

  test('should fetch all cves', async () => {
    const response = createInfoEntitiesResponse([
      {
        _id: '1',
        name: 'Admin',
        cve: {
          severity: 10.0,
        },
      },
      {
        _id: '2',
        name: 'User',
        cve: {
          severity: 5.0,
        },
      },
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new CvesCommand(fakeHttp);
    const result = await cmd.getAll();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_info', info_type: 'cve', filter: 'first=1 rows=-1'},
    });
    expect(result.data).toEqual([
      new Cve({
        id: '1',
        name: 'Admin',
        severity: 10.0,
      }),
      new Cve({
        id: '2',
        name: 'User',
        severity: 5.0,
      }),
    ]);
  });

  test('should fetch cves through native API when available', async () => {
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

  test('should fetch severity aggregates', async () => {
    const response = createAggregatesResponse({});
    const fakeHttp = createHttp(response);

    const cmd = new CvesCommand(fakeHttp);
    const result = await cmd.getSeverityAggregates();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_aggregate',
        aggregate_type: 'cve',
        group_column: 'severity',
        info_type: 'cve',
      },
    });
    expect(result.data).toEqual({groups: []});
  });

  test('should fetch created aggregates', async () => {
    const response = createAggregatesResponse({});
    const fakeHttp = createHttp(response);

    const cmd = new CvesCommand(fakeHttp);
    const result = await cmd.getCreatedAggregates();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_aggregate',
        aggregate_type: 'cve',
        group_column: 'created',
        info_type: 'cve',
      },
    });
    expect(result.data).toEqual({groups: []});
  });
});
