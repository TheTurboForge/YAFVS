/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {
  NativeScheduleBulkDeleteError,
  ScheduleCommand,
  SchedulesCommand,
} from 'gmp/native-api/schedules';
import {createActionResultResponse, createHttp} from 'gmp/commands/testing';
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
    (path: string) => `https://yafvs.example/${path}`,
  );
  fakeHttp.session = createSession();
  fakeHttp.session.token = 'test-token';
  fakeHttp.session.jwt = 'jwt-token';
  return fakeHttp;
};

const TEST_ICALENDAR =
  'BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\nDTSTART:20210104T115400Z\nDURATION:PT0S\nUID:test-schedule\nDTSTAMP:20210111T134141Z\nEND:VEVENT\nEND:VCALENDAR';

describe('ScheduleCommand tests', () => {
  test('should fetch schedule detail through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'schedule-id',
        name: 'Daily schedule',
        comment: 'Native metadata',
        timezone: 'UTC',
        icalendar: TEST_ICALENDAR,
        tasks: [{id: 'task-id', name: 'Daily task'}],
        user_tags: [{id: 'tag-id', name: 'owner', value: 'ops'}],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new ScheduleCommand(fakeHttp);
    const result = await cmd.get({id: 'schedule-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/schedules/schedule-id',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/schedules/schedule-id',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data.id).toEqual('schedule-id');
    expect(result.data.name).toEqual('Daily schedule');
  });

  test('should fetch schedule task detail filter through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'schedule-id',
        name: 'Daily schedule',
        comment: 'Native metadata',
        timezone: 'UTC',
        icalendar: TEST_ICALENDAR,
        tasks: [{id: 'task-id', name: 'Daily task'}],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new ScheduleCommand(fakeHttp);
    const result = await cmd.get({id: 'schedule-id'}, {filter: 'tasks=1'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/schedules/schedule-id',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalled();
    expect(result.data.id).toEqual('schedule-id');
    expect(result.data.tasks[0]?.id).toEqual('task-id');
  });

  test('should fetch schedule alert detail filter through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'schedule-id',
        name: 'Daily schedule',
        comment: 'Native metadata',
        timezone: 'UTC',
        icalendar: TEST_ICALENDAR,
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new ScheduleCommand(fakeHttp);
    const result = await cmd.get({id: 'schedule-id'}, {filter: 'alerts=1'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/schedules/schedule-id',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalled();
    expect(result.data.id).toEqual('schedule-id');
    expect(result.data.name).toEqual('Daily schedule');
  });

  test('should reject unsupported native schedule detail filters', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScheduleCommand(fakeHttp);

    await expect(
      cmd.get({id: 'schedule-id'}, {filter: 'results=1'}),
    ).rejects.toThrow('Native schedule detail filter is not supported');

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should create a schedule through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'created-schedule-id'}),
      ok: true,
      status: 201,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new ScheduleCommand(fakeHttp);
    const result = await cmd.create({
      name: 'created-schedule',
      comment: 'calendar-bearing create',
      icalendar: 'BEGIN:VCALENDAR\nEND:VCALENDAR',
      timezone: 'UTC',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/schedules');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/schedules',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-YAFVS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({
          name: 'created-schedule',
          comment: 'calendar-bearing create',
          timezone: 'UTC',
          icalendar: 'BEGIN:VCALENDAR\nEND:VCALENDAR',
        }),
      },
    );
    expect(result.data.id).toEqual('created-schedule-id');
  });

  test('should export schedule metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'schedule-id',
        name: 'Daily schedule',
        timezone: 'UTC',
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

    const cmd = new ScheduleCommand(fakeHttp);
    const result = await cmd.export({id: 'schedule-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/schedules/schedule-id/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/schedules/schedule-id/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: 'schedule-id',
      name: 'Daily schedule',
      timezone: 'UTC',
    });
  });

  test('should clone a schedule through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-schedule-clone-id'}),
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

    const cmd = new ScheduleCommand(fakeHttp);
    const result = await cmd.clone({id: 'schedule-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/schedules/schedule-id/clone',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/schedules/schedule-id/clone',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-YAFVS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({}),
      },
    );
    expect(result.data.id).toEqual('native-schedule-clone-id');
  });

  test('should report native schedule clone failures without GMP fallback', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'disabled'}}),
      ok: false,
      status: 503,
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

    const cmd = new ScheduleCommand(fakeHttp);
    await expect(cmd.clone({id: 'schedule-id'})).rejects.toThrow(
      'Native API request failed with status 503',
    );

    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should delete a schedule through native API when available', async () => {
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

    const cmd = new ScheduleCommand(fakeHttp);
    await cmd.delete({id: 'schedule-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/schedules/schedule-id',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/schedules/schedule-id',
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

  test('should not fall back to GMP when native schedule delete fails', async () => {
    const response = createActionResultResponse({id: 'fallback-schedule-id'});
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

    const cmd = new ScheduleCommand(fakeHttp);

    await expect(cmd.delete({id: 'schedule-id'})).rejects.toThrow(
      'Native API request failed with status 409',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should save schedule metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing
        .fn()
        .mockResolvedValue({id: 'schedule-id', name: 'updated-schedule'}),
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

    const cmd = new ScheduleCommand(fakeHttp);
    const result = await cmd.save({
      id: 'schedule-id',
      name: 'updated-schedule',
      comment: 'metadata only',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/schedules/schedule-id',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/schedules/schedule-id',
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
          name: 'updated-schedule',
          comment: 'metadata only',
        }),
      },
    );
    expect(result.data.id).toEqual('schedule-id');
  });

  test('should save calendar and timezone through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'saved-schedule-id'}),
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

    const cmd = new ScheduleCommand(fakeHttp);
    const result = await cmd.save({
      id: 'schedule-id',
      name: 'updated-schedule',
      comment: 'calendar-bearing',
      icalendar: 'BEGIN:VCALENDAR\nEND:VCALENDAR',
      timezone: 'UTC',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/schedules/schedule-id',
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
          name: 'updated-schedule',
          comment: 'calendar-bearing',
          icalendar: 'BEGIN:VCALENDAR\nEND:VCALENDAR',
          timezone: 'UTC',
        }),
      },
    );
    expect(result.data.id).toEqual('saved-schedule-id');
  });

  test('should omit absent calendar fields from native schedule patch', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'schedule-id'}),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScheduleCommand(fakeHttp);

    await cmd.save({
      id: 'schedule-id',
      name: 'updated-schedule',
      timezone: 'Europe/Berlin',
    });

    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/schedules/schedule-id',
      expect.objectContaining({
        body: JSON.stringify({
          name: 'updated-schedule',
          timezone: 'Europe/Berlin',
        }),
      }),
    );
  });
});

describe('SchedulesCommand tests', () => {
  test('should bulk export selected schedules through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 's1', name: 'Daily'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 's2', name: 'Weekly'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new SchedulesCommand(fakeHttp);

    const result = await cmd.exportByIds(['s1', 's2']);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/schedules/s1/export',
      {token: 'test-token'},
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/schedules/s2/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).schedules).toEqual([
      {id: 's1', name: 'Daily'},
      {id: 's2', name: 'Weekly'},
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
            filter: 'daily',
          },
          items: [{id: 's2', name: 'Daily B', icalendar: TEST_ICALENDAR}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 's2', name: 'Daily B'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new SchedulesCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=daily');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/schedules', {
      token: 'test-token',
      page: 2,
      page_size: 1,
      sort: 'name',
      filter: 'daily',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/schedules/s2/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).schedules).toEqual([
      {id: 's2', name: 'Daily B'},
    ]);
  });

  test('should bulk export all filtered schedules through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'name',
            filter: 'daily',
          },
          items: [{id: 's1', name: 'Daily A', icalendar: TEST_ICALENDAR}],
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
            filter: 'daily',
          },
          items: [{id: 's2', name: 'Daily B', icalendar: TEST_ICALENDAR}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 's1', name: 'Daily A'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 's2', name: 'Daily B'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new SchedulesCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=daily').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/schedules', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'daily',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/schedules', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'name',
      filter: 'daily',
    });
    expect(JSON.parse(result.data).schedules).toEqual([
      {id: 's1', name: 'Daily A'},
      {id: 's2', name: 'Daily B'},
    ]);
  });

  test('should list schedules through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: 'daily'},
        items: [{id: 's1', name: 'Daily A', icalendar: TEST_ICALENDAR}],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new SchedulesCommand(fakeHttp);

    const result = await cmd.get({filter: 'first=1 rows=25 search=daily'});

    expect(result.data.map(schedule => schedule.id)).toEqual(['s1']);
    expect(result.meta.filter).toBeInstanceOf(Filter);
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/schedules', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: 'daily',
    });
  });

  test('should get all schedules through bounded native pages', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'name',
            filter: 'daily',
          },
          items: [{id: 's1', name: 'Daily A', icalendar: TEST_ICALENDAR}],
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
            filter: 'daily',
          },
          items: [{id: 's2', name: 'Daily B', icalendar: TEST_ICALENDAR}],
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new SchedulesCommand(fakeHttp);

    const result = await cmd.getAll({
      filter: 'first=1 rows=1 search=daily',
    });

    expect(result.data.map(schedule => schedule.id)).toEqual(['s1', 's2']);
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/schedules', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'daily',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/schedules', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'name',
      filter: 'daily',
    });
  });

  test('should delete selected schedules sequentially through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({ok: true, status: 204})
      .mockResolvedValueOnce({ok: true, status: 204});
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new SchedulesCommand(fakeHttp);

    const result = await cmd.deleteByIds(['s1', 's2']);

    expect(result.data).toEqual(['s1', 's2']);
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/schedules/s1');
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/schedules/s2');
  });

  test('should report deleted, failed, and pending IDs after partial deletion', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({ok: true, status: 204})
      .mockResolvedValueOnce({ok: false, status: 503});
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new SchedulesCommand(fakeHttp);

    await expect(cmd.deleteByIds(['s1', 's2', 's3'])).rejects.toMatchObject({
      name: 'NativeScheduleBulkDeleteError',
      deletedIds: ['s1'],
      failedId: 's2',
      pendingIds: ['s2', 's3'],
    } satisfies Partial<NativeScheduleBulkDeleteError>);
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledTimes(2);
  });

  test('should repeatedly drain page one for all-filter deletion', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'name',
            filter: 'daily',
          },
          items: [
            {id: 's1', name: 'Daily A', icalendar: TEST_ICALENDAR},
            {id: 's2', name: 'Daily B', icalendar: TEST_ICALENDAR},
          ],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({ok: true, status: 204})
      .mockResolvedValueOnce({ok: true, status: 204})
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 0,
            sort: 'name',
            filter: 'daily',
          },
          items: [],
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new SchedulesCommand(fakeHttp);

    const result = await cmd.deleteByFilter(
      Filter.fromString('first=1 rows=1 search=daily').all(),
    );

    expect(result.data.map(schedule => schedule.id)).toEqual(['s1', 's2']);
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/schedules', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'daily',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/schedules/s1');
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(3, 'api/v1/schedules/s2');
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(4, 'api/v1/schedules', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'daily',
    });
  });
});
