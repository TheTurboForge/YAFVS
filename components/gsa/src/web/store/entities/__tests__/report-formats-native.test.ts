/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {
  fetchNativeReportFormat,
  fetchNativeReportFormats,
} from 'gmp/native-api/report-formats';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API report formats', () => {
  test('fetches top-level report formats as inherited ReportFormat models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: ''},
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
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeReportFormats(gmp, {
      page: 1,
      pageSize: 25,
      sort: 'name',
      filter: '',
    });

    const format = response.reportFormats[0];
    expect(response.counts.filtered).toEqual(1);
    expect(format.id).toEqual('a994b278-1f62-11e1-96ac-406186ea4fc5');
    expect(format.name).toEqual('XML');
    expect(format.summary).toEqual('Machine-readable report format');
    expect(format.extension).toEqual('xml');
    expect(format.content_type).toEqual('text/xml');
    expect(format.isActive()).toEqual(true);
    expect(format.isTrusted()).toEqual(true);
    expect(format.predefined).toEqual(true);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/report-formats', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: '',
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

  test('fetches report format details with backlinks', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'a994b278-1f62-11e1-96ac-406186ea4fc5',
        name: 'XML',
        description: 'Full XML report payload.',
        trust: 'yes',
        active: true,
        alerts: [
          {
            id: '4e110580-5281-4e8e-bbc5-322f3ef8d9e8',
            name: 'Send report',
          },
        ],
        report_configs: [
          {
            id: 'afde48df-7f26-4b2b-9c1e-03b0e1bfb3a6',
            name: 'Default config',
          },
        ],
        params: [
          {
            name: 'StringParam',
            type: 'string',
            value: 'ABC',
            default: 'DEF',
            min: 0,
            max: 100,
            options: [],
          },
          {
            name: 'SelectionParam',
            type: 'selection',
            value: 'opt1',
            default: 'opt2',
            options: [{value: 'opt1'}, {value: 'opt2'}],
          },
          {
            name: 'MultiParam',
            type: 'multi_selection',
            value: '["one"]',
            default: '[]',
            options: [{value: 'one'}, {value: 'two'}],
          },
          {
            name: 'FormatListParam',
            type: 'report_format_list',
            value: 'a994b278-1f62-11e1-96ac-406186ea4fc5,c402cc3e-b531-11e1-9163-406186ea4fc5',
            default: 'a994b278-1f62-11e1-96ac-406186ea4fc5',
            options: [],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const format = await fetchNativeReportFormat(
      gmp,
      'a994b278-1f62-11e1-96ac-406186ea4fc5',
    );

    expect(format.id).toEqual('a994b278-1f62-11e1-96ac-406186ea4fc5');
    expect(format.alerts).toHaveLength(1);
    expect(format.alerts[0].name).toEqual('Send report');
    expect(format.report_configs).toHaveLength(1);
    expect(format.report_configs[0].name).toEqual('Default config');
    expect(format.params).toHaveLength(4);
    expect(format.params[0].name).toEqual('StringParam');
    expect(format.params[0].type).toEqual('string');
    expect(format.params[0].value).toEqual('ABC');
    expect(format.params[0].default).toEqual('DEF');
    expect(format.params[1].options).toEqual([
      {name: 'opt1', value: 'opt1'},
      {name: 'opt2', value: 'opt2'},
    ]);
    expect(format.params[2].value).toEqual(['one']);
    expect(format.params[3].type).toEqual('report_format_list');
    expect(format.params[3].value).toEqual([
      'a994b278-1f62-11e1-96ac-406186ea4fc5',
      'c402cc3e-b531-11e1-9163-406186ea4fc5',
    ]);
    expect(format.params[3].default).toEqual([
      'a994b278-1f62-11e1-96ac-406186ea4fc5',
    ]);
  });
});
