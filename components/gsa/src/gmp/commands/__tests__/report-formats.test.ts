/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import ReportFormatCommand from 'gmp/commands/report-format';
import {ReportFormatsCommand} from 'gmp/commands/report-formats';
import {
  createActionResultResponse,
  createEntitiesResponse,
  createHttp,
} from 'gmp/commands/testing';
import {ALL_FILTER} from 'gmp/models/filter';
import ReportFormat from 'gmp/models/report-format';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('ReportFormatsCommand tests', () => {
  test('should import report format through inherited GMP action', async () => {
    const response = createActionResultResponse({
      action: 'import_report_format',
      id: 'report-format-id',
      message: 'Imported Report Format',
    });
    const fakeHttp = createHttp(response);

    const cmd = new ReportFormatCommand(fakeHttp);
    await cmd.import({xmlFile: '<get_report_formats_response />'});

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'import_report_format',
        xml_file: '<get_report_formats_response />',
      },
    });
  });

  test('should export report format metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'report-format-id',
        name: 'XML',
        extension: 'xml',
        content_type: 'text/xml',
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

    const cmd = new ReportFormatCommand(fakeHttp);
    const result = await cmd.export({id: 'report-format-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/report-formats/report-format-id/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/report-formats/report-format-id/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: 'report-format-id',
      name: 'XML',
      extension: 'xml',
      content_type: 'text/xml',
    });
  });

  test('should fall back to GMP when native report format metadata export fails', async () => {
    const response = createActionResultResponse({
      action: 'bulk_export',
      id: 'fallback-export-id',
      message: 'Exported Report Format',
    });
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'disabled'}}),
      ok: false,
      status: 503,
    });
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

    const cmd = new ReportFormatCommand(fakeHttp);
    await cmd.export({id: 'report-format-id'});

    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'bulk_export',
        resource_type: 'report_format',
        bulk_select: 1,
        'bulk_selected:report-format-id': 1,
      },
    });
  });

  test('should return report formats through inherited GMP fallback', async () => {
    const response = createEntitiesResponse('report_format', [
      {_id: '1', name: 'XML'},
      {_id: '2', name: 'PDF'},
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new ReportFormatsCommand(fakeHttp);
    const resp = await cmd.get();

    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_report_formats'},
    });
    expect(resp.data).toEqual([
      new ReportFormat({id: '1', name: 'XML'}),
      new ReportFormat({id: '2', name: 'PDF'}),
    ]);
  });

  test('should fetch all report formats through inherited GMP fallback', async () => {
    const response = createEntitiesResponse('report_format', [
      {_id: '1', name: 'XML'},
      {_id: '2', name: 'PDF'},
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new ReportFormatsCommand(fakeHttp);
    const resp = await cmd.getAll();

    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_report_formats',
        filter: ALL_FILTER.toFilterString(),
      },
    });
    expect(resp.data.length).toEqual(2);
  });

  test('should fetch report formats through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: 'xml'},
        items: [
          {
            id: 'a994b278-1f62-11e1-96ac-406186ea4fc5',
            name: 'XML',
            summary: 'Machine-readable report format',
            extension: 'xml',
            content_type: 'text/xml',
            trust: 'yes',
            active: true,
            predefined: true,
            configurable: false,
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

    const cmd = new ReportFormatsCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=xml'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('a994b278-1f62-11e1-96ac-406186ea4fc5');
    expect(result.data[0].name).toEqual('XML');
    expect(result.data[0].extension).toEqual('xml');
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/report-formats', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: 'xml',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/report-formats',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });
});
