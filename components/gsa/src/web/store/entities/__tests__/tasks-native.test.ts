/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {fetchNativeTask, fetchNativeTasks} from 'gmp/native-api/tasks';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API task list', () => {
  test('fetches task metadata and preserves report and scanner fields', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: 'task-1',
            name: 'Full and fast',
            comment: 'authorized LAN scan',
            status: 'Done',
            progress: 100,
            trend: 'same',
            usage_type: 'scan',
            target: {id: 'target-1', name: 'LAN target'},
            config: {id: 'config-1', name: 'Full and fast'},
            scanner: {id: 'scanner-1', name: 'Default scanner'},
            scanner_type: 2,
            schedule: {id: 'schedule-1', name: 'Weekly'},
            report_count: {total: 3, finished: 2},
            last_report: {
              id: 'report-1',
              timestamp: '2026-06-18T20:00:00Z',
              scan_start: '2026-06-18T19:00:00Z',
              scan_end: '2026-06-18T20:00:00Z',
              severity: 7.5,
            },
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeTasks(gmp, {
      page: 1,
      pageSize: 25,
      sort: 'name',
      filter: '',
    });

    const task = response.tasks[0];
    expect(response.counts.filtered).toEqual(1);
    expect(task.name).toEqual('Full and fast');
    expect(task.status).toEqual('Done');
    expect(task.progress).toEqual(100);
    expect(task.trend).toEqual('same');
    expect(task.report_count?.total).toEqual(3);
    expect(task.report_count?.finished).toEqual(2);
    expect(task.last_report?.id).toEqual('report-1');
    expect(task.last_report?.severity).toEqual(7.5);
    expect(task.target?.id).toEqual('target-1');
    expect(task.config?.name).toEqual('Full and fast');
    expect(task.scanner?.id).toEqual('scanner-1');
    expect(task.scanner?.scannerType).toEqual('2');
    expect(task.schedule?.id).toEqual('schedule-1');
    expect(task.isWritable()).toEqual(true);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/tasks', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tasks',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('fetches one task from the native detail endpoint', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'task-1',
        name: 'Full and fast',
        comment: 'authorized LAN scan',
        status: 'Done',
        progress: 100,
        trend: '',
        usage_type: 'scan',
        target: {id: 'target-1', name: 'LAN target'},
        config: {id: 'config-1', name: 'Full and fast'},
        scanner: {id: 'scanner-1', name: 'Default scanner'},
        scanner_type: 2,
        report_count: {total: 1, finished: 1},
        last_report: {id: 'report-1', severity: 7.5},
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeTask(gmp, 'task-1');

    expect(response.task.id).toEqual('task-1');
    expect(response.task.name).toEqual('Full and fast');
    expect(response.task.report_count?.total).toEqual(1);
    expect(response.task.scanner?.scannerType).toEqual('2');
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/tasks/task-1', {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tasks/task-1',
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
