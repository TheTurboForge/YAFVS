/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import DfnCertAdvisoriesCommand from 'gmp/commands/dfn-cert-advisories';
import {
  createAggregatesResponse,
  createHttp,
  createInfoEntitiesResponse,
} from 'gmp/commands/testing';
import DfnCertAdv from 'gmp/models/dfn-cert';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('DfnCertAdvisoriesCommand tests', () => {
  test('should fetch dfn cert advisories with default params', async () => {
    const response = createInfoEntitiesResponse([
      {
        _id: '1',
        name: 'Admin',
        dfn_cert_adv: {
          severity: 10.0,
        },
      },
      {
        _id: '2',
        name: 'User',
        dfn_cert_adv: {
          severity: 5.0,
        },
      },
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new DfnCertAdvisoriesCommand(fakeHttp);
    const result = await cmd.get();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_info', info_type: 'dfn_cert_adv'},
    });
    expect(result.data).toEqual([
      new DfnCertAdv({
        id: '1',
        name: 'Admin',
        severity: 10.0,
      }),
      new DfnCertAdv({
        id: '2',
        name: 'User',
        severity: 5.0,
      }),
    ]);
  });

  test('should fetch dfn cert advisories with custom params', async () => {
    const response = createInfoEntitiesResponse([
      {
        _id: '1',
        name: 'Admin',
        dfn_cert_adv: {
          severity: 10.0,
        },
      },
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new DfnCertAdvisoriesCommand(fakeHttp);
    const result = await cmd.get({filter: "name='Admin'"});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_info',
        info_type: 'dfn_cert_adv',
        filter: "name='Admin'",
      },
    });
    expect(result.data).toEqual([
      new DfnCertAdv({
        id: '1',
        name: 'Admin',
        severity: 10.0,
      }),
    ]);
  });

  test('should fetch all dfn cert advisories', async () => {
    const response = createInfoEntitiesResponse([
      {
        _id: '1',
        name: 'Admin',
        dfn_cert_adv: {
          severity: 10.0,
        },
      },
      {
        _id: '2',
        name: 'User',
        dfn_cert_adv: {
          severity: 5.0,
        },
      },
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new DfnCertAdvisoriesCommand(fakeHttp);
    const result = await cmd.getAll();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_info',
        info_type: 'dfn_cert_adv',
        filter: 'first=1 rows=-1',
      },
    });
    expect(result.data).toEqual([
      new DfnCertAdv({
        id: '1',
        name: 'Admin',
        severity: 10.0,
      }),
      new DfnCertAdv({
        id: '2',
        name: 'User',
        severity: 5.0,
      }),
    ]);
  });

  test('should fetch DFN-CERT advisories through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: '-created', filter: 'openssl'},
        items: [
          {
            id: 'dfn-cert-uuid-1',
            name: 'DFN-CERT-2026-001',
            title: 'Example DFN-CERT advisory',
            severity: 8.7,
            cve_refs: 2,
            cves: ['CVE-2026-10001', 'CVE-2026-10002'],
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

    const cmd = new DfnCertAdvisoriesCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=openssl'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('dfn-cert-uuid-1');
    expect(result.data[0].title).toEqual('Example DFN-CERT advisory');
    expect(result.data[0].severity).toEqual(8.7);
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/dfn-cert-advisories',
      {
        token: 'test-token',
        page: 1,
        page_size: 25,
        sort: 'created',
        filter: 'openssl',
      },
    );
  });

  test('should fetch severity aggregates', async () => {
    const response = createAggregatesResponse({});
    const fakeHttp = createHttp(response);

    const cmd = new DfnCertAdvisoriesCommand(fakeHttp);
    const result = await cmd.getSeverityAggregates();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_aggregate',
        aggregate_type: 'dfn_cert_adv',
        group_column: 'severity',
        info_type: 'dfn_cert_adv',
      },
    });
    expect(result.data).toEqual({groups: []});
  });

  test('should fetch created aggregates', async () => {
    const response = createAggregatesResponse({});
    const fakeHttp = createHttp(response);

    const cmd = new DfnCertAdvisoriesCommand(fakeHttp);
    const result = await cmd.getCreatedAggregates();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_aggregate',
        aggregate_type: 'dfn_cert_adv',
        group_column: 'created',
        info_type: 'dfn_cert_adv',
      },
    });
    expect(result.data).toEqual({groups: []});
  });
});
