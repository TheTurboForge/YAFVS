/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {
  fetchNativeSchedule,
  fetchNativeSchedules,
} from 'gmp/native-api/schedules';

const ICALENDAR = `BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
DTSTART:20260619T120000Z
DURATION:PT1H
UID:turbo-schedule-test
DTSTAMP:20260619T100000Z
END:VEVENT
END:VCALENDAR`;

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
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
    expect(schedule.event).toBeDefined();
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/schedules', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/schedules',
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
    expect(schedule.tasks[0].id).toEqual('65da9d26-9e74-4b56-af0f-63825a851a23');
    expect(schedule.tasks[0].name).toEqual('Authorized LAN task');
    expect(schedule.event).toBeDefined();
  });
});
