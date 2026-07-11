/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import ReportCommand from 'gmp/commands/report';
import {createHttp} from 'gmp/commands/testing';
import {createSession} from 'gmp/testing';

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

describe('ReportCommand tests', () => {
  test('should request single report through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'foo',
        name: 'Report Foo',
        status: 'Done',
        result_count: 7,
        vulnerability_count: 3,
        host_count: 2,
        cve_count: 1,
        severity: {
          critical: 0,
          high: 1,
          medium: 2,
          low: 0,
          log: 0,
          false_positive: 0,
        },
        max_severity: 8.1,
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new ReportCommand(fakeHttp);
    const resp = await cmd.get({id: 'foo'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/reports/foo', {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/reports/foo',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    const {data} = resp;
    expect(data.id).toEqual('foo');
    expect(data.name).toEqual('Report Foo');
  });
});
