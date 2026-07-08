/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {ScheduleCommand, SchedulesCommand} from 'gmp/commands/schedules';
import {
  createActionResultResponse,
  createHttp,
  createPlainResponse,
} from 'gmp/commands/testing';
import Filter from 'gmp/models/filter';
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

const TEST_ICALENDAR =
  'BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\nDTSTART:20210104T115400Z\nDURATION:PT0S\nUID:test-schedule\nDTSTAMP:20210111T134141Z\nEND:VEVENT\nEND:VCALENDAR';

describe('ScheduleCommand tests', () => {
  test('should keep schedule create on inherited GMP when native API is available', async () => {
    const response = createActionResultResponse({id: 'created-schedule-id'});
    const fetchMock = testing.fn();
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
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new ScheduleCommand(fakeHttp);
    const result = await cmd.create({
      name: 'created-schedule',
      comment: 'calendar-bearing create',
      icalendar: 'BEGIN:VCALENDAR\nEND:VCALENDAR',
      timezone: 'UTC',
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'create_schedule',
        name: 'created-schedule',
        comment: 'calendar-bearing create',
        icalendar: 'BEGIN:VCALENDAR\nEND:VCALENDAR',
        timezone: 'UTC',
      },
    });
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
      (path: string) => `https://turbovas.example/${path}`,
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
      'https://turbovas.example/api/v1/schedules/schedule-id/export',
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
      (path: string) => `https://turbovas.example/${path}`,
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
      'https://turbovas.example/api/v1/schedules/schedule-id/clone',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-TurboVAS-Token': 'test-token',
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
      (path: string) => `https://turbovas.example/${path}`,
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
      (path: string) => `https://turbovas.example/${path}`,
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
      'https://turbovas.example/api/v1/schedules/schedule-id',
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
      (path: string) => `https://turbovas.example/${path}`,
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
      (path: string) => `https://turbovas.example/${path}`,
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
      'https://turbovas.example/api/v1/schedules/schedule-id',
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
          name: 'updated-schedule',
          comment: 'metadata only',
        }),
      },
    );
    expect(result.data.id).toEqual('schedule-id');
  });

  test('should keep calendar-bearing schedule save on GMP', async () => {
    const response = createActionResultResponse({id: 'saved-schedule-id'});
    const fetchMock = testing.fn();
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

    const cmd = new ScheduleCommand(fakeHttp);
    const result = await cmd.save({
      id: 'schedule-id',
      name: 'updated-schedule',
      comment: 'calendar-bearing',
      icalendar: 'BEGIN:VCALENDAR\nEND:VCALENDAR',
      timezone: 'UTC',
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_schedule',
        schedule_id: 'schedule-id',
        name: 'updated-schedule',
        comment: 'calendar-bearing',
        icalendar: 'BEGIN:VCALENDAR\nEND:VCALENDAR',
        timezone: 'UTC',
      },
    });
    expect(result.data.id).toEqual('saved-schedule-id');
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
          page: {page: 2, page_size: 1, total: 3, sort: 'name', filter: 'daily'},
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
          page: {page: 1, page_size: 500, total: 2, sort: 'name', filter: 'daily'},
          items: [{id: 's1', name: 'Daily A', icalendar: TEST_ICALENDAR}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 500, total: 2, sort: 'name', filter: 'daily'},
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
});
