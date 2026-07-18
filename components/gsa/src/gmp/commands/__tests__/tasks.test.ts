/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import TasksCommand from 'gmp/commands/tasks';
import {
  createHttp,
  createEntitiesResponse,
  createAggregatesResponse,
} from 'gmp/commands/testing';
import Filter from 'gmp/models/filter';
import Task from 'gmp/models/task';
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
    (path: string) => `https://yafvs.example/${path}`,
  );
  fakeHttp.session = createSession();
  fakeHttp.session.token = 'test-token';
  fakeHttp.session.jwt = 'jwt-token';
  return fakeHttp;
};

describe('TasksCommand tests', () => {
  test('should fetch tasks with default params', async () => {
    const response = createEntitiesResponse('task', [
      {_id: '1', name: 'Scan Task 1'},
      {_id: '2', name: 'Scan Task 2'},
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new TasksCommand(fakeHttp);
    const result = await cmd.get();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_tasks', usage_type: 'scan'},
    });
    expect(result.data).toEqual([
      new Task({id: '1', name: 'Scan Task 1'}),
      new Task({id: '2', name: 'Scan Task 2'}),
    ]);
  });

  test('should fetch tasks with custom params', async () => {
    const response = createEntitiesResponse('task', [
      {_id: '3', name: 'Custom Task'},
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new TasksCommand(fakeHttp);
    const result = await cmd.get({filter: "name='Custom Task'"});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_tasks',
        filter: "name='Custom Task'",
        usage_type: 'scan',
      },
    });
    expect(result.data).toEqual([new Task({id: '3', name: 'Custom Task'})]);
  });

  test('should fetch tasks with schedules only', async () => {
    const response = createEntitiesResponse('task', [
      {_id: '3', name: 'Custom Task'},
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new TasksCommand(fakeHttp);
    const result = await cmd.get({schedulesOnly: true});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_tasks',
        usage_type: 'scan',
        schedules_only: 1,
      },
    });
    expect(result.data).toEqual([new Task({id: '3', name: 'Custom Task'})]);
  });

  test('should fetch all tasks', async () => {
    const response = createEntitiesResponse('task', [
      {_id: '4', name: 'All Tasks 1'},
      {_id: '5', name: 'All Tasks 2'},
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new TasksCommand(fakeHttp);
    const result = await cmd.getAll();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_tasks', filter: 'first=1 rows=-1', usage_type: 'scan'},
    });
    expect(result.data).toEqual([
      new Task({id: '4', name: 'All Tasks 1'}),
      new Task({id: '5', name: 'All Tasks 2'}),
    ]);
  });

  test('should fetch all tasks with schedules only', async () => {
    const response = createEntitiesResponse('task', [
      {_id: '4', name: 'All Tasks 1'},
      {_id: '5', name: 'All Tasks 2'},
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new TasksCommand(fakeHttp);
    const result = await cmd.getAll({schedulesOnly: true});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_tasks',
        filter: 'first=1 rows=-1',
        usage_type: 'scan',
        schedules_only: 1,
      },
    });
    expect(result.data).toEqual([
      new Task({id: '4', name: 'All Tasks 1'}),
      new Task({id: '5', name: 'All Tasks 2'}),
    ]);
  });

  test('should fetch tasks through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: 'scan'},
        items: [
          {
            id: 'task-1',
            name: 'Native scan task',
            comment: 'native task metadata',
            status: 'Done',
            progress: 100,
            trend: 'same',
            usage_type: 'scan',
            target: {id: 'target-1', name: 'Web target'},
            config: {id: 'config-1', name: 'Full and fast'},
            scanner: {id: 'scanner-1', name: 'Default scanner'},
            scanner_type: 2,
            report_count: {total: 1, finished: 1},
            last_report: {id: 'report-1', severity: 5.5},
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new TasksCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=scan'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('task-1');
    expect(result.data[0].name).toEqual('Native scan task');
    expect(result.data[0].status).toEqual('Done');
    expect(result.data[0].report_count?.total).toEqual(1);
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/tasks', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: 'scan',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/tasks',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('should bulk export selected tasks through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'task-1', name: 'One'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'task-2', name: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TasksCommand(fakeHttp);

    const result = await cmd.export([
      new Task({id: 'task-1'}),
      new Task({id: 'task-2'}),
    ]);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/tasks/task-1/export',
      {token: 'test-token'},
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/tasks/task-2/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).tasks).toEqual([
      {id: 'task-1', name: 'One'},
      {id: 'task-2', name: 'Two'},
    ]);
  });

  test('should bulk export current page tasks through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 1, total: 3, sort: 'name', filter: 'scan'},
          items: [{id: 'task-2', name: 'Two'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'task-2', name: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TasksCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=scan');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/tasks', {
      token: 'test-token',
      page: 2,
      page_size: 1,
      sort: 'name',
      filter: 'scan',
    });
    expect(JSON.parse(result.data).tasks).toEqual([
      {id: 'task-2', name: 'Two'},
    ]);
  });

  test('should bulk export all filtered tasks through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'name',
            filter: 'scan',
          },
          items: [{id: 'task-1', name: 'One'}],
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
            filter: 'scan',
          },
          items: [{id: 'task-2', name: 'Two'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'task-1', name: 'One'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'task-2', name: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TasksCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=scan').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/tasks', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'scan',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/tasks', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'name',
      filter: 'scan',
    });
    expect(JSON.parse(result.data).tasks).toEqual([
      {id: 'task-1', name: 'One'},
      {id: 'task-2', name: 'Two'},
    ]);
  });

  test('should fetch schedules-only task lists through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 500, total: 1, sort: 'name', filter: ''},
        items: [{id: 'scheduled-task-1', name: 'Scheduled Task'}],
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
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new TasksCommand(fakeHttp);
    const result = await cmd.getAll({schedulesOnly: true});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/tasks', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: '',
      schedules_only: 'true',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/tasks',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data).toHaveLength(1);
    expect(result.data[0].id).toEqual('scheduled-task-1');
    expect(result.data[0].name).toEqual('Scheduled Task');
  });

  test('should fetch severity aggregates', async () => {
    const response = createAggregatesResponse({});
    const fakeHttp = createHttp(response);

    const cmd = new TasksCommand(fakeHttp);
    const result = await cmd.getSeverityAggregates();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_aggregate',
        aggregate_type: 'task',
        group_column: 'severity',
        usage_type: 'scan',
      },
    });
    expect(result.data).toEqual({groups: []});
  });

  test('should fetch status aggregates', async () => {
    const response = createAggregatesResponse({});
    const fakeHttp = createHttp(response);

    const cmd = new TasksCommand(fakeHttp);
    const result = await cmd.getStatusAggregates();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_aggregate',
        aggregate_type: 'task',
        group_column: 'status',
        usage_type: 'scan',
      },
    });
    expect(result.data).toEqual({groups: []});
  });

  test('should fetch high results aggregates', async () => {
    const response = createAggregatesResponse({});
    const fakeHttp = createHttp(response);

    const cmd = new TasksCommand(fakeHttp);
    const result = await cmd.getHighResultsAggregates();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_aggregate',
        aggregate_type: 'task',
        group_column: 'uuid',
        usage_type: 'scan',
        'sort_fields:0': 'high_per_host',
        'sort_fields:1': 'modified',
        'sort_orders:0': 'descending',
        'sort_orders:1': 'descending',
        'sort_stats:0': 'max',
        'sort_stats:1': 'value',
        'text_columns:0': 'name',
        'text_columns:1': 'high_per_host',
        'text_columns:2': 'severity',
        'text_columns:3': 'modified',
      },
    });
    expect(result.data).toEqual({groups: []});
  });
});
