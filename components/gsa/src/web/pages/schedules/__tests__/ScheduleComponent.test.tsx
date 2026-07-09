/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, expect, test, testing} from '@gsa/testing';
import {fireEvent, rendererWith, screen, wait} from 'web/testing';
import date, {duration} from 'gmp/models/date';
import Event from 'gmp/models/event';
import Schedule from 'gmp/models/schedule';
import {createSession} from 'gmp/testing';
import Button from 'web/components/form/Button';
import ScheduleComponent, {
  metadataOnlyScheduleSaveData,
} from 'web/pages/schedules/ScheduleComponent';

const createGmp = ({
  currentSettings = testing.fn().mockResolvedValue({}),
  exportSchedule = testing
    .fn()
    .mockResolvedValue({data: '<schedule id="123"/>'}),
  native = false,
  saveSchedule = testing.fn().mockResolvedValue({}),
} = {}) => ({
  ...(native
    ? {
        buildUrl: testing.fn(
          (path, _params) => `https://turbovas.example/${path}`,
        ),
      }
    : {}),
  session: {...createSession({timezone: 'UTC'}), token: 'test-token'},
  schedule: {export: exportSchedule, save: saveSchedule},
  user: {currentSettings},
});

describe('ScheduleComponent tests', () => {
  test('should render', async () => {
    const gmp = createGmp();
    const {render} = rendererWith({gmp});

    render(
      <ScheduleComponent>
        {() => <Button data-testid="button" />}
      </ScheduleComponent>,
    );

    expect(screen.getByTestId('button')).toBeInTheDocument();
  });

  test('should open New Schedule dialog', async () => {
    const gmp = createGmp();

    const {render} = rendererWith({
      gmp,
      capabilities: true,
    });

    render(
      <ScheduleComponent>
        {({create}) => <Button data-testid="button" onClick={() => create()} />}
      </ScheduleComponent>,
    );

    const button = screen.getByTestId('button');

    fireEvent.click(button);

    const dialog = screen.getDialog();
    expect(dialog).toBeInTheDocument();

    const dialogTile = screen.getDialogTitle();
    expect(dialogTile).toHaveTextContent('New Schedule');
  });

  test('should open new schedule dialog', async () => {
    const gmp = createGmp();

    const {render} = rendererWith({
      gmp,
      capabilities: true,
    });

    render(
      <ScheduleComponent>
        {({create}) => <Button data-testid="button" onClick={create} />}
      </ScheduleComponent>,
    );

    const button = screen.getByTestId('button');

    fireEvent.click(button);

    const dialog = screen.getDialog();
    expect(dialog).toBeInTheDocument();

    const dialogTile = screen.getDialogTitle();
    expect(dialogTile).toHaveTextContent('New Schedule');
  });

  test('should open edit schedule dialog', async () => {
    const gmp = createGmp();
    const schedule = new Schedule({
      id: '1',
      name: 'Test Schedule',
      comment: 'This is a test schedule',
      timezone: 'CET',
      event: Event.fromData(
        {
          startDate: date('2024-01-01T12:00:00Z'),
          duration: duration({seconds: 3600}),
          freq: 'WEEKLY',
        },
        'CET',
      ),
    });

    const {render} = rendererWith({
      gmp,
      capabilities: true,
    });

    render(
      <ScheduleComponent>
        {({edit}) => (
          <Button data-testid="button" onClick={() => edit(schedule)} />
        )}
      </ScheduleComponent>,
    );

    const button = screen.getByTestId('button');

    fireEvent.click(button);

    const dialog = screen.getDialog();
    expect(dialog).toBeInTheDocument();

    const dialogTile = screen.getDialogTitle();
    expect(dialogTile).toHaveTextContent('Edit Schedule Test Schedule');

    expect(screen.getByRole('textbox', {name: 'Name'})).toHaveValue(
      'Test Schedule',
    );
    expect(screen.getByRole('textbox', {name: 'Comment'})).toHaveValue(
      'This is a test schedule',
    );
  });

  test('should use native metadata export for downloads', async () => {
    const nativePayload = {
      id: '123',
      name: 'Native Schedule',
      comment: 'native metadata',
      timezone: 'UTC',
    };
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue(nativePayload),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({
      currentSettings: testing.fn().mockResolvedValue({
        data: {
          detailsexportfilename: {
            id: 'details-export-filename',
            name: 'Details Export File Name',
            value: '%T-%U',
          },
        },
      }),
      native: true,
    });
    const schedule = new Schedule({id: '123', name: 'Native Schedule'});
    const onDownloaded = testing.fn();
    const onDownloadError = testing.fn();
    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <ScheduleComponent
        onDownloadError={onDownloadError}
        onDownloaded={onDownloaded}
      >
        {({download}) => (
          <Button data-testid="button" onClick={() => download(schedule)} />
        )}
      </ScheduleComponent>,
    );

    await wait();
    fireEvent.click(screen.getByTestId('button'));
    await wait();

    expect(gmp.schedule.export).not.toHaveBeenCalled();
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/schedules/123/export', {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalledExactlyOnceWith(
      'https://turbovas.example/api/v1/schedules/123/export',
      expect.objectContaining({credentials: 'include'}),
    );
    expect(onDownloaded).toHaveBeenCalledWith({
      filename: 'schedule-123.json',
      data: `${JSON.stringify(nativePayload, null, 2)}\n`,
    });
    expect(onDownloadError).not.toHaveBeenCalled();
  });

  test('should strip unchanged-calendar metadata edits to native patch shape', () => {
    const startDate = date('2024-01-01T12:00:00Z');
    const scheduleDuration = duration({seconds: 3600});
    const icalendar = Event.fromData(
      {
        startDate,
        duration: scheduleDuration,
        freq: 'WEEKLY',
        interval: 1,
        summary: 'Updated Schedule',
        description: 'This is a test schedule',
        uid: 'schedule-event-uid',
      },
      'UTC',
    ).toIcalString();

    expect(
      metadataOnlyScheduleSaveData(
        {
          id: '1',
          name: 'Updated Schedule',
          comment: 'This is a test schedule',
          icalendar,
          timezone: 'UTC',
        },
        {
          startDate,
          duration: scheduleDuration,
          eventUid: 'schedule-event-uid',
          freq: 'WEEKLY',
          interval: 1,
          scheduleTimezone: 'UTC',
        },
      ),
    ).toEqual({
      id: '1',
      name: 'Updated Schedule',
      comment: 'This is a test schedule',
    });
  });

  test('should keep changed-calendar schedule edits on full save shape', () => {
    const startDate = date('2024-01-01T12:00:00Z');
    const scheduleDuration = duration({seconds: 3600});
    const changedCalendar = Event.fromData(
      {
        startDate,
        duration: duration({seconds: 7200}),
        freq: 'WEEKLY',
        interval: 1,
        summary: 'Updated Schedule',
        description: 'This is a test schedule',
        uid: 'schedule-event-uid',
      },
      'UTC',
    ).toIcalString();
    const data = {
      id: '1',
      name: 'Updated Schedule',
      comment: 'This is a test schedule',
      icalendar: changedCalendar,
      timezone: 'UTC',
    };

    expect(
      metadataOnlyScheduleSaveData(data, {
        startDate,
        duration: scheduleDuration,
        eventUid: 'schedule-event-uid',
        freq: 'WEEKLY',
        interval: 1,
        scheduleTimezone: 'UTC',
      }),
    ).toBe(data);
  });
});
