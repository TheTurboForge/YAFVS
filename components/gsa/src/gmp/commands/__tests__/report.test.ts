/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import ReportCommand from 'gmp/commands/report';
import {
  createHttp,
  createHttpError,
} from 'gmp/commands/testing';
import {ResponseRejection} from 'gmp/http/rejection';
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

  test('should request report metrics through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'foo',
        summary: {
          alive_system_count: 2,
          total_system_cvss_load: 12.5,
          average_system_cvss_load: 6.25,
          vulnerability_count: 3,
          authenticated_system_count: 1,
          authentication_failed_system_count: 0,
          no_credential_path_system_count: 1,
          unknown_authentication_system_count: 0,
          authenticated_scan_coverage_percent: 50,
        },
        systems: [],
        vulnerabilities: [],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new ReportCommand(fakeHttp);
    const resp = await cmd.getMetrics({id: 'foo'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/reports/foo/metrics',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/reports/foo/metrics',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(resp.data.id).toEqual('foo');
    expect(resp.data.summary.averageSystemCvssLoad).toEqual(6.25);
  });

  test('should allow to download a report', async () => {
    const data = new ArrayBuffer(8);
    const fakeHttp = createHttp(data);
    const cmd = new ReportCommand(fakeHttp);
    const response = await cmd.download(
      {id: 'report-uuid'},
      {
        reportConfigId: 'config-uuid',
        reportFormatId: 'format-uuid',
      },
    );
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_report',
        details: 1,
        report_id: 'report-uuid',
        report_config_id: 'config-uuid',
        report_format_id: 'format-uuid',
        filter: 'first=1 rows=-1',
      },
      responseType: 'arraybuffer',
    });
    expect(response).toBe(data);
  });

  test('should transform error during report download', async () => {
    const error = new ResponseRejection<string>(
      {status: 500} as XMLHttpRequest,
      'some error',
      '<gsad_message>Some error</gsad_message>',
    );
    const http = createHttpError(error);
    const cmd = new ReportCommand(http);
    await expect(
      cmd.download(
        {id: 'report-uuid'},
        {
          reportConfigId: 'config-uuid',
          reportFormatId: 'format-uuid',
        },
      ),
    ).rejects.toThrow('some error');
  });
});
