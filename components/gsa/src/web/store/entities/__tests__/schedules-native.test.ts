/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {
  fetchNativeSchedule,
  fetchNativeSchedules,
} from 'gmp/native-api/schedules';
import Filter from 'gmp/models/filter';
import Schedule from 'gmp/models/schedule';
import {loadEntities, loadEntity} from 'web/store/entities/schedules';
import {createState} from 'web/store/entities/utils/testing';
import {filterIdentifier} from 'web/store/utils';

const ICALENDAR = `BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
DTSTART:20260619T120000Z
DURATION:PT1H
UID:turbo-schedule-test
DTSTAMP:20260619T100000Z
END:VEVENT
END:VCALENDAR`;

const createGmp = ({
  jwt,
  token = 'test-token',
}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://yafvs.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API schedules', () => {
  test('fetches top-level schedules as inherited Schedule models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: '07f0569c-38a7-4c8c-9a13-0e5f3c119c95',
            name: 'Weekly LAN scan',
            comment: 'Existing schedule',
            icalendar: ICALENDAR,
            timezone: 'UTC',
            timezone_abbrev: 'UTC',
            tasks: [],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeSchedules(gmp, {
      page: 1,
      pageSize: 25,
      sort: 'name',
      filter: '',
    });

    const schedule = response.schedules[0];
    expect(response.counts.filtered).toEqual(1);
    expect(schedule.id).toEqual('07f0569c-38a7-4c8c-9a13-0e5f3c119c95');
    expect(schedule.name).toEqual('Weekly LAN scan');
    expect(schedule.comment).toEqual('Existing schedule');
    expect(schedule.timezone).toEqual('UTC');
    expect(schedule.tasks).toHaveLength(0);
    expect(schedule.isWritable()).toEqual(true);
    expect(schedule.userCapabilities.mayEdit('schedule')).toEqual(true);
    expect(schedule.userCapabilities.mayDelete('schedule')).toEqual(true);
    expect(schedule.event).toBeDefined();
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/schedules', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/schedules',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('fetches schedule details with task backlinks', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: '07f0569c-38a7-4c8c-9a13-0e5f3c119c95',
        name: 'Weekly LAN scan',
        icalendar: ICALENDAR,
        timezone: 'UTC',
        tasks: [
          {
            id: '65da9d26-9e74-4b56-af0f-63825a851a23',
            name: 'Authorized LAN task',
            usage_type: 'scan',
          },
        ],
        user_tags: [
          {
            id: '8afbe92e-f808-447c-9399-1492f3f9ef3f',
            name: 'Maintenance window',
            value: 'weekly',
            comment: 'Native schedule tag',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const schedule = await fetchNativeSchedule(
      gmp,
      '07f0569c-38a7-4c8c-9a13-0e5f3c119c95',
    );

    expect(schedule.id).toEqual('07f0569c-38a7-4c8c-9a13-0e5f3c119c95');
    expect(schedule.tasks).toHaveLength(1);
    expect(schedule.tasks[0].id).toEqual(
      '65da9d26-9e74-4b56-af0f-63825a851a23',
    );
    expect(schedule.tasks[0].name).toEqual('Authorized LAN task');
    expect(schedule.userTags).toHaveLength(1);
    expect(schedule.userTags[0].id).toEqual(
      '8afbe92e-f808-447c-9399-1492f3f9ef3f',
    );
    expect(schedule.userTags[0].name).toEqual('Maintenance window');
    expect(schedule.userTags[0].value).toEqual('weekly');
    expect(schedule.userTags[0].comment).toEqual('Native schedule tag');
    expect(schedule.event).toBeDefined();
  });

  test('loads the schedule store through same-origin native API', async () => {
    const filter = Filter.fromString('first=1 rows=10 sort=name');
    const rootState = createState('schedule', {
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
            id: '07f0569c-38a7-4c8c-9a13-0e5f3c119c95',
            name: 'Weekly LAN scan',
            comment: 'Existing schedule',
            icalendar: ICALENDAR,
            timezone: 'UTC',
            timezone_abbrev: 'UTC',
            tasks: [],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();

    await loadEntities(gmp)(filter)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/schedules', {
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
    expect(successAction.data[0]).toBeInstanceOf(Schedule);
    expect(successAction.data[0].name).toEqual('Weekly LAN scan');
  });

  test('loads native detail without inherited GMP double-read', async () => {
    const id = '07f0569c-38a7-4c8c-9a13-0e5f3c119c95';
    const rootState = createState('schedule', {
      isLoading: {
        [id]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id,
        name: 'Weekly LAN scan',
        icalendar: ICALENDAR,
        timezone: 'UTC',
        tasks: [],
        user_tags: [
          {
            id: '8afbe92e-f808-447c-9399-1492f3f9ef3f',
            name: 'Maintenance window',
            value: 'weekly',
            comment: 'Native schedule tag',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      ...createGmp({jwt: 'jwt-token'}),
      schedule: {
        get: testing
          .fn()
          .mockRejectedValue(new Error('inherited fallback used')),
      },
    };

    await loadEntity(gmp)(id)(dispatch, getState);

    expect(gmp.schedule.get).not.toHaveBeenCalled();
    expect(gmp.buildUrl).toHaveBeenCalledWith(`api/v1/schedules/${id}`, {
      token: 'test-token',
    });
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITY_LOADING_SUCCESS');
    expect(successAction.id).toEqual(id);
    expect(successAction.data).toBeInstanceOf(Schedule);
    expect(successAction.data.name).toEqual('Weekly LAN scan');
    expect(successAction.data.userTags[0].name).toEqual('Maintenance window');
  });
});
