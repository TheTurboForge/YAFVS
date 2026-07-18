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
import TaskCommand from 'gmp/native-api/task-command';
import {isNativeTaskMutationOutcomeUncertain} from 'gmp/native-api/tasks';
import {
  createActionResultResponse,
  createHttp,
  createPlainResponse,
} from 'gmp/commands/testing';
import logger, {type LogLevel} from 'gmp/log';
import {createSession} from 'gmp/testing';

let logLevel: LogLevel;

const nativeJsonResponse = (payload: unknown, status = 200) => ({
  json: testing.fn().mockResolvedValue(payload),
  ok: status >= 200 && status < 300,
  status,
});

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
      (path: string) => 'https://yafvs.example/' + path,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    await new TaskCommand(fakeHttp).start({id: 'task/id'});

    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/tasks/task%2Fid/start',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/tasks/task%2Fid/start',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-YAFVS-Token': 'test-token',
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
      (path: string) => 'https://yafvs.example/' + path,
    );
    fakeHttp.session = createSession();

    await expect(
      new TaskCommand(fakeHttp).start({id: 'task-id'}),
    ).rejects.toThrow('Native API request failed with status 409');
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
      (path: string) => 'https://yafvs.example/' + path,
    );
    fakeHttp.session = createSession();

    await expect(
      new TaskCommand(fakeHttp).start({id: 'task-id'}),
    ).rejects.toThrow('Feed is currently syncing. Please try again later.');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('should stop a task through native API when available', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: testing.fn().mockResolvedValue({
          task_id: 'task-id',
          status: 'stopped',
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: testing.fn().mockResolvedValue({
          id: 'task-id',
          name: 'Stopped task',
          status: 'Stopped',
        }),
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
    const cmd = new TaskCommand(fakeHttp);

    const response = await cmd.stop({id: 'task-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/tasks/task-id/stop',
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/tasks/task-id',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'https://yafvs.example/api/v1/tasks/task-id/stop',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-YAFVS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: '{}',
      },
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'https://yafvs.example/api/v1/tasks/task-id',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(response.data.id).toEqual('task-id');
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
      (path: string) => `https://yafvs.example/${path}`,
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
      (path: string) => 'https://yafvs.example/' + path,
    );
    fakeHttp.session = createSession();

    await expect(
      new TaskCommand(fakeHttp).stop({id: 'task-id'}),
    ).rejects.toThrow('Native API request failed with status 409');
    expect(fakeHttp.request).not.toHaveBeenCalled();
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
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new TaskCommand(fakeHttp);

    await cmd.delete({id: 'task-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/tasks/task-id');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/tasks/task-id',
      {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'X-YAFVS-Token': 'test-token',
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
      (path: string) => `https://yafvs.example/${path}`,
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
      (path: string) => `https://yafvs.example/${path}`,
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
      'https://yafvs.example/api/v1/tasks/task-id/export',
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

  test('should clone a task through native API with the returned task detail', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'cloned-task-id',
        name: 'Cloned task',
        comment: 'native clone',
        status: 'New',
        target: {id: 'target-id', name: 'Target'},
        config: {id: 'config-id', name: 'Config'},
      }),
      ok: true,
      status: 201,
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
    const cmd = new TaskCommand(fakeHttp);

    const result = await cmd.clone({id: 'task/id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/tasks/task%2Fid/clone',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/tasks/task%2Fid/clone',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'X-YAFVS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data.id).toEqual('cloned-task-id');
  });

  test('should not fall back to GMP when native task clone fails', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: false,
      status: 409,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(
      createActionResultResponse({id: 'fallback-task-id'}),
    ) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    await expect(
      new TaskCommand(fakeHttp).clone({id: 'task-id'}),
    ).rejects.toThrow('Native API request failed with status 409');
    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test.each([
    [
      'committed_response_unavailable',
      'The mutation committed, but its response could not be completed; verify current state before retrying.',
    ],
    [
      'mutation_outcome_indeterminate',
      'The mutation may have committed, but no authoritative response was received; verify current state before retrying.',
    ],
  ])(
    'should surface structured native task clone error %s without payload or GMP fallback',
    async (code, apiMessage) => {
      const payload = 'TASK CLONE PAYLOAD MUST NOT LEAK';
      const fetchMock = testing.fn().mockResolvedValue(
        nativeJsonResponse(
          {
            error: {
              code,
              message: apiMessage,
              payload,
            },
          },
          502,
        ),
      );
      testing.stubGlobal('fetch', fetchMock);
      const fakeHttp = createHttp(
        createActionResultResponse({id: 'fallback-task-id'}),
      ) as ReturnType<typeof createHttp> & {
        buildUrl: ReturnType<typeof testing.fn>;
        session: ReturnType<typeof createSession>;
      };
      fakeHttp.buildUrl = testing.fn(
        (path: string) => `https://yafvs.example/${path}`,
      );
      fakeHttp.session = createSession();
      fakeHttp.session.token = 'test-token';
      const cmd = new TaskCommand(fakeHttp);

      let caught: unknown;
      try {
        await cmd.clone({id: 'task-id'});
      } catch (error) {
        caught = error;
      }

      expect(caught).toMatchObject({
        code,
        message: `Native API request failed with status 502: ${code}: ${apiMessage}`,
      });
      expect(caught).not.toHaveProperty('payload');
      expect((caught as Error).message).not.toContain(payload);
      expect(fakeHttp.request).not.toHaveBeenCalled();
    },
  );

  test.each([
    'committed_response_unavailable',
    'mutation_outcome_indeterminate',
  ])('should classify uncertain native task start error %s', async code => {
    const payload = 'TASK START PAYLOAD MUST NOT LEAK';
    const fetchMock = testing.fn().mockResolvedValue(
      nativeJsonResponse(
        {
          error: {
            code,
            message: 'verify task state before retrying',
            payload,
          },
        },
        502,
      ),
    );
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(
      createPlainResponse(JSON.stringify({items: []})),
    ) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();

    let caught: unknown;
    try {
      await new TaskCommand(fakeHttp).start({id: 'task1'});
    } catch (error) {
      caught = error;
    }

    expect(isNativeTaskMutationOutcomeUncertain(caught)).toEqual(true);
    expect((caught as Error).message).not.toContain(payload);
    expect(fakeHttp.request).toHaveBeenCalledTimes(1);
  });

  test('should create a task through native API with retained editor fields', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'task1', name: 'foo'}),
      ok: true,
      status: 201,
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

    const cmd = new TaskCommand(fakeHttp);
    const response = await cmd.create({
      add_tag: 1,
      alert_ids: ['alert1'],
      apply_overrides: 0,
      comment: 'comment',
      config_id: 'config1',
      max_checks: 10,
      max_hosts: 11,
      min_qod: 65,
      name: 'foo',
      scanner_id: 'scanner1',
      schedule_id: 'schedule1',
      schedule_periods: 1,
      tag_id: 'tag1',
      target_id: 'target1',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/tasks',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-YAFVS-Token': 'test-token',
        },
        body: JSON.stringify({
          name: 'foo',
          comment: 'comment',
          target_id: 'target1',
          config_id: 'config1',
          scanner_id: 'scanner1',
          schedule_id: 'schedule1',
          schedule_periods: 1,
          alert_ids: ['alert1'],
          hosts_ordering: 'random',
          apply_overrides: false,
          max_checks: 10,
          max_hosts: 11,
          min_qod: 65,
          tag_id: 'tag1',
        }),
      },
    );
    expect(response?.data.id).toEqual('task1');
  });

  test('should not retry native task create through GMP after failure', async () => {
    const fetchMock = testing
      .fn()
      .mockRejectedValue(new Error('native task create failed'));
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

    const cmd = new TaskCommand(fakeHttp);

    await expect(
      cmd.create({
        config_id: 'config1',
        name: 'foo',
        scanner_id: 'scanner1',
        target_id: 'target1',
      }),
    ).rejects.toThrow('native task create failed');
    expect(fakeHttp.request).not.toHaveBeenCalled();
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
      (path: string) => `https://yafvs.example/${path}`,
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
      'https://yafvs.example/api/v1/tasks/task1',
      {
        method: 'PATCH',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-YAFVS-Token': 'test-token',
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

  test('should replace operational task configuration through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'task1', name: 'foo'}),
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

    const cmd = new TaskCommand(fakeHttp);
    const response = await cmd.save({
      apply_overrides: 0,
      comment: 'comment',
      config_id: 'config1',
      hosts_ordering: 'reverse',
      id: 'task1',
      max_checks: 10,
      max_hosts: 10,
      min_qod: 70,
      name: 'foo',
      scanner_id: 'scanner1',
      schedule_id: 'schedule1',
      schedule_periods: 3,
      target_id: 'target1',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/tasks/task1/replace-configuration',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/tasks/task1/replace-configuration',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-YAFVS-Token': 'test-token',
        },
        body: JSON.stringify({
          name: 'foo',
          comment: 'comment',
          target_id: 'target1',
          config_id: 'config1',
          scanner_id: 'scanner1',
          schedule_id: 'schedule1',
          schedule_periods: 3,
          alert_ids: [],
          hosts_ordering: 'reverse',
          apply_overrides: false,
          max_checks: 10,
          max_hosts: 10,
          min_qod: 70,
        }),
      },
    );
    expect(response?.data.id).toEqual('task1');
  });

  test('should not retry native task replacement through GMP after failure', async () => {
    const fetchMock = testing
      .fn()
      .mockRejectedValue(new Error('native task replacement failed'));
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

    const cmd = new TaskCommand(fakeHttp);

    await expect(
      cmd.save({
        config_id: 'config1',
        id: 'task1',
        name: 'foo',
        scanner_id: 'scanner1',
        target_id: 'target1',
      }),
    ).rejects.toThrow('native task replacement failed');
    expect(fakeHttp.request).not.toHaveBeenCalled();
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
