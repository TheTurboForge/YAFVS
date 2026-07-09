/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {
  fetchNativeReportConfig,
  fetchNativeReportConfigs,
} from 'gmp/native-api/report-configs';
import Filter from 'gmp/models/filter';
import {loadEntities, loadEntity} from 'web/store/entities/reportconfigs';
import {createState} from 'web/store/entities/utils/testing';
import {filterIdentifier} from 'web/store/utils';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API report configs', () => {
  test('fetches report configs as inherited ReportConfig models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: 'afde48df-7f26-4b2b-9c1e-03b0e1bfb3a6',
            name: 'Default config',
            comment: 'default XML settings',
            owner: {name: 'admin'},
            report_format: {
              id: 'a994b278-1f62-11e1-96ac-406186ea4fc5',
              name: 'XML',
            },
            writable: true,
            in_use: false,
            orphan: false,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeReportConfigs(gmp, {
      page: 1,
      pageSize: 25,
      sort: 'name',
      filter: '',
    });

    const config = response.reportConfigs[0];
    expect(response.counts.filtered).toEqual(1);
    expect(config.id).toEqual('afde48df-7f26-4b2b-9c1e-03b0e1bfb3a6');
    expect(config.name).toEqual('Default config');
    expect(config.owner?.name).toEqual('admin');
    expect(config.reportFormat?.name).toEqual('XML');
    expect(config.isWritable()).toEqual(true);
    expect(config.isInUse()).toEqual(false);
    expect(config.userCapabilities.mayEdit('report_config')).toEqual(true);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/report-configs', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/report-configs',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('fetches report config details with params and backlinks', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'afde48df-7f26-4b2b-9c1e-03b0e1bfb3a6',
        name: 'Default config',
        in_use: true,
        report_format: {
          id: 'a994b278-1f62-11e1-96ac-406186ea4fc5',
          name: 'XML',
        },
        alerts: [
          {
            id: '4e110580-5281-4e8e-bbc5-322f3ef8d9e8',
            name: 'Send report',
          },
        ],
        params: [
          {
            name: 'Format',
            type: 'report_format_list',
            value: 'a994b278-1f62-11e1-96ac-406186ea4fc5',
            default: 'a994b278-1f62-11e1-96ac-406186ea4fc5',
            using_default: true,
            value_report_formats: [
              {
                id: 'a994b278-1f62-11e1-96ac-406186ea4fc5',
                name: 'XML',
              },
            ],
            default_report_formats: [
              {
                id: 'a994b278-1f62-11e1-96ac-406186ea4fc5',
                name: 'XML',
              },
            ],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const config = await fetchNativeReportConfig(
      gmp,
      'afde48df-7f26-4b2b-9c1e-03b0e1bfb3a6',
    );

    expect(config.reportFormat?.name).toEqual('XML');
    expect(config.isInUse()).toEqual(true);
    expect(config.alerts).toHaveLength(1);
    expect(config.alerts[0].name).toEqual('Send report');
    expect(config.params).toHaveLength(1);
    expect(config.params[0].value).toEqual([
      'a994b278-1f62-11e1-96ac-406186ea4fc5',
    ]);
    expect(config.params[0].valueLabels?.['a994b278-1f62-11e1-96ac-406186ea4fc5']).toEqual('XML');
    expect(config.params[0].valueUsingDefault).toEqual(true);
  });

  test('loads the report config store through same-origin native API', async () => {
    const filter = Filter.fromString('first=1 rows=10 sort=name');
    const rootState = createState('reportconfig', {
      isLoading: {
        [filterIdentifier(filter)]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 10, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: 'afde48df-7f26-4b2b-9c1e-03b0e1bfb3a6',
            name: 'Default config',
            report_format: {
              id: 'a994b278-1f62-11e1-96ac-406186ea4fc5',
              name: 'XML',
            },
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    await loadEntities(gmp)(filter)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/report-configs', {
      token: 'test-token',
      page: 1,
      page_size: 10,
      sort: 'name',
      filter: '',
    });
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITIES_LOADING_SUCCESS');
    expect(successAction.counts.filtered).toEqual(1);
    expect(successAction.data[0].name).toEqual('Default config');
  });

  test('loads report config detail store entries through same-origin native API', async () => {
    const id = 'afde48df-7f26-4b2b-9c1e-03b0e1bfb3a6';
    const rootState = createState('reportconfig', {
      isLoading: {
        [id]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id,
        name: 'Default config',
        report_format: {
          id: 'a994b278-1f62-11e1-96ac-406186ea4fc5',
          name: 'XML',
        },
        params: [],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    await loadEntity(gmp)(id)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/report-configs/afde48df-7f26-4b2b-9c1e-03b0e1bfb3a6',
      {token: 'test-token'},
    );
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITY_LOADING_SUCCESS');
    expect(successAction.data.name).toEqual('Default config');
  });
});
