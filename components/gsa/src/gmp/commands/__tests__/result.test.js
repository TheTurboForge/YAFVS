/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {ResultCommand} from 'gmp/commands/result';
import {createHttp} from 'gmp/commands/testing';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('ResultCommand tests', () => {
  test('should fetch single result through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'result-id',
        host: '192.0.2.1',
        port: '443/tcp',
        nvt_oid: '1.3.6.1.4.1.25623.1.0.1',
        name: 'Native result',
        severity: 7.5,
        qod: 80,
        source_report_id: 'report-id',
        raw_evidence_href: '/reports/report-id/results/result-id',
        description: 'Native detail body',
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined);
    fakeHttp.buildUrl = testing.fn(
      (path, _params) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new ResultCommand(fakeHttp);

    const result = await cmd.get({id: 'result-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/results/result-id', {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/results/result-id',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data.id).toEqual('result-id');
    expect(result.data.name).toEqual('Native result');
    expect(result.data.description).toEqual('Native detail body');
  });

  test('should not fall back to GMP when native result detail fails', async () => {
    testing.stubGlobal(
      'fetch',
      testing.fn().mockResolvedValue({
        json: testing.fn().mockResolvedValue({message: 'missing'}),
        ok: false,
        status: 404,
      }),
    );
    const fakeHttp = createHttp(undefined);
    fakeHttp.buildUrl = testing.fn(
      (path, _params) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new ResultCommand(fakeHttp);

    await expect(cmd.get({id: 'missing-result'})).rejects.toThrow(
      'Native API request failed with status 404',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should export result metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'result-id',
        name: 'Example finding',
        severity: 7.5,
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined);
    fakeHttp.buildUrl = testing.fn(
      (path, _params) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new ResultCommand(fakeHttp);

    const result = await cmd.export({id: 'result-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/results/result-id/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/results/result-id/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: 'result-id',
      name: 'Example finding',
      severity: 7.5,
    });
  });
});
