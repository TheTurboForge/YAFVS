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
  createHttp,
  createResponse,
} from 'gmp/commands/testing';
import Filter from 'gmp/models/filter';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

const createNativeHttp = (response?: Parameters<typeof createHttp>[0]) => {
  const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
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

describe('ReportFormatsCommand tests', () => {
  test('should fetch report format detail through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'report-format-id',
        name: 'XML',
        summary: 'Machine-readable report format',
        extension: 'xml',
        content_type: 'text/xml',
        active: true,
        configurable: true,
        params: [{name: 'StringParam', type: 'string', value: 'ABC'}],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new ReportFormatCommand(fakeHttp);
    const result = await cmd.get({id: 'report-format-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/report-formats/report-format-id',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/report-formats/report-format-id',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data.id).toEqual('report-format-id');
    expect(result.data.name).toEqual('XML');
    expect(result.data.params[0].name).toEqual('StringParam');
  });

  test('should fetch report format alert detail through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'report-format-id',
        name: 'XML',
        alerts: [{id: 'alert-id', name: 'Notify SecOps'}],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new ReportFormatCommand(fakeHttp);
    const result = await cmd.get(
      {id: 'report-format-id'},
      {filter: 'alerts=1'},
    );

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/report-formats/report-format-id',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/report-formats/report-format-id',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data.id).toEqual('report-format-id');
    expect(result.data.alerts[0].id).toEqual('alert-id');
  });

  test('should keep unsupported filtered report format detail on GMP', async () => {
    const response = createResponse({
      get_report_format: {
        get_report_formats_response: {
          report_format: {
            _id: 'report-format-id',
            name: 'XML',
          },
        },
      },
    });
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp(response);

    const cmd = new ReportFormatCommand(fakeHttp);
    const result = await cmd.get(
      {id: 'report-format-id'},
      {filter: 'rows=1'},
    );

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_report_format',
        report_format_id: 'report-format-id',
        filter: 'rows=1',
      },
    });
    expect(result.data.id).toEqual('report-format-id');
  });

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

  test('should save report format metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'report-format-id'}),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new ReportFormatCommand(fakeHttp);
    const result = await cmd.save({
      active: true,
      id: 'report-format-id',
      name: 'Custom XML',
      summary: 'Custom report format',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/report-formats/report-format-id',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/report-formats/report-format-id',
      {
        method: 'PATCH',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({
          active: true,
          name: 'Custom XML',
          summary: 'Custom report format',
        }),
      },
    );
    expect(result.data).toEqual({id: 'report-format-id'});
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
    const fakeHttp = createNativeHttp();

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
    const fakeHttp = createNativeHttp();

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

  test('should bulk export selected report formats through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'rf1', name: 'XML'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'rf2', name: 'PDF'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ReportFormatsCommand(fakeHttp);

    const result = await cmd.exportByIds(['rf1', 'rf2']);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/report-formats/rf1/export',
      {token: 'test-token'},
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/report-formats/rf2/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).report_formats).toEqual([
      {id: 'rf1', name: 'XML'},
      {id: 'rf2', name: 'PDF'},
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
            filter: 'pdf',
          },
          items: [{id: 'rf2', name: 'PDF B'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'rf2', name: 'PDF B'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ReportFormatsCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=pdf');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/report-formats',
      {
        token: 'test-token',
        page: 2,
        page_size: 1,
        sort: 'name',
        filter: 'pdf',
      },
    );
    expect(JSON.parse(result.data).report_formats).toEqual([
      {id: 'rf2', name: 'PDF B'},
    ]);
  });

  test('should bulk export all filtered report formats through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'name',
            filter: 'pdf',
          },
          items: [{id: 'rf1', name: 'PDF A'}],
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
            filter: 'pdf',
          },
          items: [{id: 'rf2', name: 'PDF B'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'rf1', name: 'PDF A'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'rf2', name: 'PDF B'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ReportFormatsCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=pdf').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/report-formats',
      {
        token: 'test-token',
        page: 1,
        page_size: 500,
        sort: 'name',
        filter: 'pdf',
      },
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/report-formats',
      {
        token: 'test-token',
        page: 2,
        page_size: 500,
        sort: 'name',
        filter: 'pdf',
      },
    );
    expect(JSON.parse(result.data).report_formats).toEqual([
      {id: 'rf1', name: 'PDF A'},
      {id: 'rf2', name: 'PDF B'},
    ]);
  });
});
