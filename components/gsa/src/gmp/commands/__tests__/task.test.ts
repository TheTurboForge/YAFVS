/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {
  describe,
  test,
  expect,
  beforeAll,
  afterAll,
  testing,
} from '@gsa/testing';
import FeedStatusCommand from 'gmp/native-api/feeds';
import TaskCommand, {
  isTaskStartManagerResponseFailure,
} from 'gmp/commands/task';
import {
  createActionResultResponse,
  createHttp,
  createPlainResponse,
  createResponse,
} from 'gmp/commands/testing';
import type Http from 'gmp/http/http';
import {ResponseRejection} from 'gmp/http/rejection';
import logger, {type LogLevel} from 'gmp/log';
import {
  OPENVAS_SCANNER_TYPE,
  OPENVAS_DEFAULT_SCANNER_ID,
} from 'gmp/models/scanner';
import {
  HOSTS_ORDERING_RANDOM,
  AUTO_DELETE_KEEP_DEFAULT_VALUE,
} from 'gmp/models/task';
import {createSession} from 'gmp/testing';

let logLevel: LogLevel;

beforeAll(() => {
  logLevel = logger.level;
  logger.setDefaultLevel('silent');
});

afterAll(() => {
  logger.setDefaultLevel(logLevel);
});

describe('TaskCommand tests', () => {
  test('should start a task through native API with encoded path and headers', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: true,
      status: 202,
      json: testing.fn().mockResolvedValue({}),
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(
      createPlainResponse(JSON.stringify({items: []})),
    ) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => 'https://turbovas.example/' + path,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    await new TaskCommand(fakeHttp).start({id: 'task/id'});

    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/tasks/task%2Fid/start');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tasks/task%2Fid/start',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: '{}',
      },
    );
  });

  test('should reject native task start on non-2xx response', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: false,
      status: 409,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(
      createPlainResponse(JSON.stringify({items: []})),
    ) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => 'https://turbovas.example/' + path,
    );
    fakeHttp.session = createSession();

    await expect(new TaskCommand(fakeHttp).start({id: 'task-id'})).rejects.toThrow(
      'Native API request failed with status 409',
    );
  });

  test('should short-circuit native task start while feed is syncing', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(
      createPlainResponse(
        JSON.stringify({
          items: [
            {type: 'NVT', currently_syncing: {timestamp: '202502170647'}},
          ],
        }),
      ),
    ) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => 'https://turbovas.example/' + path,
    );
    fakeHttp.session = createSession();

    await expect(new TaskCommand(fakeHttp).start({id: 'task-id'})).rejects.toThrow(
      'Feed is currently syncing. Please try again later.',
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('should fall back to GMP task start when native API is unavailable', async () => {
    const fakeHttp = createHttp();
    const requestMock = fakeHttp.request as unknown as ReturnType<
      typeof testing.fn
    >;
    requestMock
      .mockResolvedValueOnce(
        createPlainResponse(JSON.stringify({items: []})),
      )
      .mockResolvedValueOnce(createActionResultResponse());

    await new TaskCommand(fakeHttp).start({id: 'task-id'});

    expect(fakeHttp.request).toHaveBeenNthCalledWith(2, 'post', {
      data: {cmd: 'start_task', task_id: 'task-id'},
    });
  });

  test('should stop a task through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: testing.fn().mockResolvedValue({
        task_id: 'task-id',
        status: 'stopped',
      }),
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
    const cmd = new TaskCommand(fakeHttp);
    const getMock = testing
      .spyOn(cmd, 'get')
      .mockResolvedValue(undefined as never);

    await cmd.stop({id: 'task-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/tasks/task-id/stop',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tasks/task-id/stop',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: '{}',
      },
    );
    expect(getMock).toHaveBeenCalledWith({id: 'task-id'});
  });

  test('should reject a mismatched native task stop response', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: testing.fn().mockResolvedValue({
        task_id: 'other-task',
        status: 'stopped',
      }),
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
    const cmd = new TaskCommand(fakeHttp);
    const getMock = testing
      .spyOn(cmd, 'get')
      .mockResolvedValue(undefined as never);

    await expect(cmd.stop({id: 'task-id'})).rejects.toThrow(
      'Native API returned an invalid task stop response',
    );
    expect(getMock).not.toHaveBeenCalled();
  });

  test('should not fall back to GMP when native task stop fails', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: false,
      status: 409,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(createActionResultResponse()) as ReturnType<
      typeof createHttp
    > & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => 'https://turbovas.example/' + path,
    );
    fakeHttp.session = createSession();

    await expect(new TaskCommand(fakeHttp).stop({id: 'task-id'})).rejects.toThrow(
      'Native API request failed with status 409',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should fall back to GMP task stop when native API is unavailable', async () => {
    const fakeHttp = createHttp(createActionResultResponse());
    const cmd = new TaskCommand(fakeHttp);
    const getMock = testing
      .spyOn(cmd, 'get')
      .mockResolvedValue(undefined as never);

    await cmd.stop({id: 'task-id'});

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {cmd: 'stop_task', task_id: 'task-id'},
    });
    expect(getMock).toHaveBeenCalledWith({id: 'task-id'});
  });

  test('should delete task through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: true,
      status: 204,
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
    const cmd = new TaskCommand(fakeHttp);

    await cmd.delete({id: 'task-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/tasks/task-id');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tasks/task-id',
      {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('should not fall back to GMP when native task delete fails', async () => {
    const response = createActionResultResponse({id: 'fallback-task-id'});
    const fetchMock = testing.fn().mockResolvedValue({
      ok: false,
      status: 409,
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
    const cmd = new TaskCommand(fakeHttp);

    await expect(cmd.delete({id: 'task-id'})).rejects.toThrow(
      'Native API request failed with status 409',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should export task metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'task-id',
        name: 'Native task',
        status: 'Done',
        target: {id: 'target-id', name: 'Target'},
        current_report: {id: 'report-id', timestamp: '2026-07-02T17:00:00Z'},
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
    const cmd = new TaskCommand(fakeHttp);

    const result = await cmd.export({id: 'task-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/tasks/task-id/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tasks/task-id/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: 'task-id',
      name: 'Native task',
      status: 'Done',
      target: {id: 'target-id', name: 'Target'},
      current_report: {id: 'report-id', timestamp: '2026-07-02T17:00:00Z'},
    });
  });

  test('should enrich manager response failures while starting a task', async () => {
    const xhr = {
      status: 500,
      response: '',
    } as XMLHttpRequest;
    const rejection = new ResponseRejection(
      xhr,
      'Failure to receive response from manager daemon.',
    );
    const feedStatusResponse = createPlainResponse(JSON.stringify({items: []}));
    const fakeHttp = {
      apiProtocol: 'http',
      apiServer: 'example.test',
      getParams: testing.fn().mockReturnValue({token: undefined}),
      request: testing
        .fn()
        .mockResolvedValueOnce(feedStatusResponse)
        .mockRejectedValueOnce(rejection),
    } as unknown as Http;

    const cmd = new TaskCommand(fakeHttp);
    await expect(cmd.start({id: 'task1'})).rejects.toThrow(
      'Refresh the task status and check the latest report before retrying.',
    );
    expect(isTaskStartManagerResponseFailure(rejection)).toEqual(true);
  });

  test('should create new task', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);

    const cmd = new TaskCommand(fakeHttp);
    const resp = await cmd.create({
      apply_overrides: 0,
      comment: 'comment',
      config_id: 'c1',
      max_checks: 10,
      max_hosts: 10,
      min_qod: 70,
      name: 'foo',
      scanner_id: OPENVAS_DEFAULT_SCANNER_ID,
      scanner_type: OPENVAS_SCANNER_TYPE,
      target_id: 't1',
      csAllowFailedRetrieval: true,
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        add_tag: undefined,
        'alert_ids:': [],
        apply_overrides: 0,
        auto_delete_data: AUTO_DELETE_KEEP_DEFAULT_VALUE,
        cmd: 'create_task',
        comment: 'comment',
        config_id: 'c1',
        hosts_ordering: HOSTS_ORDERING_RANDOM,
        max_checks: 10,
        max_hosts: 10,
        min_qod: 70,
        name: 'foo',
        scanner_id: OPENVAS_DEFAULT_SCANNER_ID,
        scanner_type: OPENVAS_SCANNER_TYPE,
        schedule_id: undefined,
        schedule_periods: undefined,
        tag_id: undefined,
        target_id: 't1',
        usage_type: 'scan',
        cs_allow_failed_retrieval: 1,
      },
    });
    const {data} = resp;
    expect(data.id).toEqual('foo');
  });

  test('should create new task with all parameters', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new TaskCommand(fakeHttp);
    const resp = await cmd.create({
      add_tag: 1,
      alert_ids: ['a1', 'a2'],
      apply_overrides: 0,
      auto_delete_data: AUTO_DELETE_KEEP_DEFAULT_VALUE,
      comment: 'comment',
      config_id: 'c1',
      max_checks: 10,
      max_hosts: 10,
      min_qod: 70,
      name: 'foo',
      scanner_id: OPENVAS_DEFAULT_SCANNER_ID,
      scanner_type: OPENVAS_SCANNER_TYPE,
      schedule_id: 's1',
      schedule_periods: 1,
      tag_id: 't1',
      target_id: 't1',
      csAllowFailedRetrieval: true,
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        add_tag: 1,
        'alert_ids:': ['a1', 'a2'],
        apply_overrides: 0,
        auto_delete_data: AUTO_DELETE_KEEP_DEFAULT_VALUE,
        cmd: 'create_task',
        comment: 'comment',
        config_id: 'c1',
        hosts_ordering: HOSTS_ORDERING_RANDOM,
        max_checks: 10,
        max_hosts: 10,
        min_qod: 70,
        name: 'foo',
        scanner_id: OPENVAS_DEFAULT_SCANNER_ID,
        scanner_type: OPENVAS_SCANNER_TYPE,
        schedule_id: 's1',
        schedule_periods: 1,
        tag_id: 't1',
        target_id: 't1',
        usage_type: 'scan',
        cs_allow_failed_retrieval: 1,
      },
    });
    const {data} = resp;
    expect(data.id).toEqual('foo');
  });

  test.each([
    {
      name: 'missing port list',
      message: 'Failed to find port_list XYZ',
      expectedMessage:
        'Failed to create a new Target because the default Port List is not available. This issue may be due to the feed not having completed its synchronization.\nPlease try again shortly.',
    },
    {
      name: 'missing scan config',
      message: 'Failed to find config XYZ',
      expectedMessage:
        'Failed to create a new Task because the default Scan Config is not available. This issue may be due to the feed not having completed its synchronization.\nPlease try again shortly.',
    },
  ])(
    'should not create new task while feed is not available: $name',
    async ({message, expectedMessage}) => {
      const xhr = {
        status: 404,
      } as XMLHttpRequest;
      const rejection = new ResponseRejection(xhr, message);
      const request = testing.fn().mockRejectedValue(rejection);
      const fakeHttp = {
        request,
      } as unknown as Http;

      const cmd = new TaskCommand(fakeHttp);
      await expect(
        cmd.create({
          apply_overrides: 0,
          comment: 'comment',
          config_id: 'c1',
          max_checks: 10,
          max_hosts: 10,
          min_qod: 70,
          name: 'foo',
          scanner_id: OPENVAS_DEFAULT_SCANNER_ID,
          scanner_type: OPENVAS_SCANNER_TYPE,
          target_id: 't1',
          csAllowFailedRetrieval: true,
        }),
      ).rejects.toThrow(expectedMessage);
      expect(request).toHaveBeenCalledTimes(1);
    },
  );

  test('should save task', async () => {
    const mockResponse = createActionResultResponse();
    const fakeHttp = createHttp(mockResponse);
    const cmd = new TaskCommand(fakeHttp);
    const response = await cmd.save({
      apply_overrides: 0,
      comment: 'comment',
      id: 'task1',
      max_checks: 10,
      max_hosts: 10,
      min_qod: 70,
      name: 'foo',
      csAllowFailedRetrieval: true,
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        'alert_ids:': [],
        apply_overrides: 0,
        auto_delete_data: AUTO_DELETE_KEEP_DEFAULT_VALUE,
        cmd: 'save_task',
        comment: 'comment',
        config_id: '0',
        hosts_ordering: HOSTS_ORDERING_RANDOM,
        max_checks: 10,
        max_hosts: 10,
        min_qod: 70,
        name: 'foo',
        scanner_id: '0',
        scanner_type: undefined,
        schedule_id: '0',
        schedule_periods: undefined,
        task_id: 'task1',
        target_id: '0',
        usage_type: 'scan',
        cs_allow_failed_retrieval: 1,
      },
    });
    expect(response).toBeUndefined();
  });

  test('should save task metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'task1', name: 'updated-task'}),
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

    const cmd = new TaskCommand(fakeHttp);
    const response = await cmd.save({
      id: 'task1',
      name: 'updated-task',
      comment: 'metadata only',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/tasks/task1');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tasks/task1',
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
          name: 'updated-task',
          comment: 'metadata only',
        }),
      },
    );
    expect(response?.data.id).toEqual('task1');
  });

  test('should keep operational task save on GMP when native API is available', async () => {
    const mockResponse = createActionResultResponse();
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(mockResponse) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new TaskCommand(fakeHttp);
    const response = await cmd.save({
      apply_overrides: 0,
      comment: 'comment',
      id: 'task1',
      max_checks: 10,
      max_hosts: 10,
      min_qod: 70,
      name: 'foo',
      csAllowFailedRetrieval: true,
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: expect.objectContaining({
        cmd: 'save_task',
        task_id: 'task1',
        max_checks: 10,
      }),
    });
    expect(response).toBeUndefined();
  });

  test.each([
    {
      name: 'missing port list',
      message: 'Failed to find port_list XYZ',
      expectedMessage:
        'Failed to create a new Target because the default Port List is not available. This issue may be due to the feed not having completed its synchronization.\nPlease try again shortly.',
    },
    {
      name: 'missing scan config',
      message: 'Failed to find config XYZ',
      expectedMessage:
        'Failed to create a new Task because the default Scan Config is not available. This issue may be due to the feed not having completed its synchronization.\nPlease try again shortly.',
    },
  ])(
    'should not save task while feed is not available: $name',
    async ({message, expectedMessage}) => {
      const xhr = {
        status: 404,
      };
      const rejection = new ResponseRejection(xhr as XMLHttpRequest, message);
      const request = testing.fn().mockRejectedValue(rejection);
      const fakeHttp = {
        request,
      } as unknown as Http;

      const cmd = new TaskCommand(fakeHttp);
      await expect(
        cmd.save({
          apply_overrides: 0,
          comment: 'comment',
          id: 'task1',
          max_checks: 10,
          max_hosts: 10,
          min_qod: 70,
          name: 'foo',
          csAllowFailedRetrieval: true,
        }),
      ).rejects.toThrow(expectedMessage);
      expect(request).toHaveBeenCalledTimes(1);
    },
  );

  test('should save task with all parameters', async () => {
    const mockResponse = createActionResultResponse();
    const fakeHttp = createHttp(mockResponse);
    const cmd = new TaskCommand(fakeHttp);
    const response = await cmd.save({
      alert_ids: ['a1', 'a2'],
      apply_overrides: 0,
      auto_delete_data: AUTO_DELETE_KEEP_DEFAULT_VALUE,
      comment: 'comment',
      config_id: 'c1',
      id: 'task1',
      max_checks: 10,
      max_hosts: 10,
      min_qod: 70,
      name: 'foo',
      scanner_id: OPENVAS_DEFAULT_SCANNER_ID,
      scanner_type: OPENVAS_SCANNER_TYPE,
      schedule_id: 's1',
      schedule_periods: 1,
      target_id: 't1',
      csAllowFailedRetrieval: true,
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        'alert_ids:': ['a1', 'a2'],
        apply_overrides: 0,
        auto_delete_data: AUTO_DELETE_KEEP_DEFAULT_VALUE,
        cmd: 'save_task',
        comment: 'comment',
        config_id: 'c1',
        hosts_ordering: HOSTS_ORDERING_RANDOM,
        max_checks: 10,
        max_hosts: 10,
        min_qod: 70,
        name: 'foo',
        scanner_id: OPENVAS_DEFAULT_SCANNER_ID,
        scanner_type: OPENVAS_SCANNER_TYPE,
        schedule_id: 's1',
        schedule_periods: 1,
        task_id: 'task1',
        target_id: 't1',
        usage_type: 'scan',
        cs_allow_failed_retrieval: 1,
      },
    });
    expect(response).toBeUndefined();
  });

  test('should throw an error if feed is currently syncing', async () => {
    const response = createPlainResponse(
      JSON.stringify({
        items: [
          {
            type: 'NVT',
            currently_syncing: {timestamp: '202502170647'},
            sync_not_available: false,
            version: '202502170647',
          },
          {
            type: 'SCAP',
            sync_not_available: false,
            version: '202502170647',
          },
        ],
      }),
    );
    const fakeHttp = createHttp(response);

    const taskCmd = new TaskCommand(fakeHttp);

    const feedCmd = new FeedStatusCommand(fakeHttp);

    const result = await feedCmd.checkFeedSync();
    expect(result.isSyncing).toBe(true);

    await expect(taskCmd.start({id: 'task1'})).rejects.toThrow(
      'Feed is currently syncing. Please try again later.',
    );
  });




});
