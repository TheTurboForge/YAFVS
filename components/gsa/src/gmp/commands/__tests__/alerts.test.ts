/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import AlertsCommand from 'gmp/commands/alerts';
import {createHttp, createEntitiesResponse} from 'gmp/commands/testing';
import Alert from 'gmp/models/alert';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('AlertsCommand tests', () => {
  test('should fetch alerts with default params', async () => {
    const response = createEntitiesResponse('alert', [
      {_id: '1', name: 'Alert1'},
      {_id: '2', name: 'Alert2'},
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new AlertsCommand(fakeHttp);
    const result = await cmd.get();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_alerts'},
    });
    expect(result.data).toEqual([
      new Alert({
        id: '1',
        name: 'Alert1',
      }),
      new Alert({
        id: '2',
        name: 'Alert2',
      }),
    ]);
  });

  test('should fetch alerts with custom params', async () => {
    const response = createEntitiesResponse('alert', [
      {_id: '3', name: 'Alert3'},
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new AlertsCommand(fakeHttp);
    const result = await cmd.get({filter: "name='Alert3'"});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_alerts', filter: "name='Alert3'"},
    });
    expect(result.data).toEqual([new Alert({id: '3', name: 'Alert3'})]);
  });

  test('should fetch all alerts', async () => {
    const response = createEntitiesResponse('alert', [
      {_id: '4', name: 'Alert4'},
      {_id: '5', name: 'Alert5'},
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new AlertsCommand(fakeHttp);
    const result = await cmd.getAll();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_alerts', filter: 'first=1 rows=-1'},
    });
    expect(result.data).toEqual([
      new Alert({id: '4', name: 'Alert4'}),
      new Alert({id: '5', name: 'Alert5'}),
    ]);
  });

  test('should fetch alerts through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: 'secops'},
        items: [
          {
            id: '4e110580-5281-4e8e-bbc5-322f3ef8d9e8',
            name: 'Notify SecOps',
            owner: {name: 'admin'},
            active: true,
            in_use: false,
            task_count: 0,
            event: {type: 'Task run status changed'},
            condition: {type: 'Filter count at least'},
            method: {type: 'SCP'},
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

    const cmd = new AlertsCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=secops'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('4e110580-5281-4e8e-bbc5-322f3ef8d9e8');
    expect(result.data[0].name).toEqual('Notify SecOps');
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/alerts', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: 'secops',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/alerts',
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
