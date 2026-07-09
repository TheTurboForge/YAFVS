/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useState} from 'react';
import {type Duration, type Date} from 'gmp/models/date';
import Event, {
  type RecurrenceFrequencyType,
  type WeekDays,
} from 'gmp/models/event';
import type Schedule from 'gmp/models/schedule';
import {isDefined} from 'gmp/utils/identity';
import {exportNativeScheduleMetadata} from 'gmp/native-api/schedules';
import EntityComponent from 'web/entity/EntityComponent';
import {type EntityCloneResponse} from 'web/entity/hooks/useEntityClone';
import {type EntityCreateResponse} from 'web/entity/hooks/useEntityCreate';
import {type OnDownloadedFunc} from 'web/entity/hooks/useEntityDownload';
import useGmp from 'web/hooks/useGmp';
import useTranslation from 'web/hooks/useTranslation';
import useUserTimezone from 'web/hooks/useUserTimezone';
import ScheduleDialog, {
  type ScheduleDialogSaveData,
} from 'web/pages/schedules/ScheduleDialog';

interface ScheduleRenderProps {
  create: () => void;
  download: (schedule: Schedule) => Promise<void>;
  edit: (schedule: Schedule) => void;
}

interface ScheduleComponentProps {
  children: (props: ScheduleRenderProps) => React.ReactNode;
  onCloned?: (data: EntityCloneResponse) => void;
  onCloneError?: (error: Error) => void;
  onCreated?: (data: EntityCreateResponse) => void;
  onCreateError?: (error: Error) => void;
  onDeleted?: () => void;
  onDeleteError?: (error: Error) => void;
  onDownloaded?: OnDownloadedFunc;
  onDownloadError?: (error: Error) => void;
  onSaved?: () => void;
  onSaveError?: (error: Error) => void;
}

const exportSchedule = (gmp: ReturnType<typeof useGmp>, schedule: Schedule) => {
  return exportNativeScheduleMetadata(gmp, schedule.id as string);
};

interface ScheduleDialogState {
  duration?: Duration;
  eventUid?: string;
  freq?: RecurrenceFrequencyType;
  interval?: number;
  monthDays?: number[];
  scheduleTimezone?: string;
  startDate?: Date;
  weekdays?: WeekDays;
}

export const metadataOnlyScheduleSaveData = (
  data: ScheduleDialogSaveData,
  state: ScheduleDialogState,
):
  | ScheduleDialogSaveData
  | Pick<ScheduleDialogSaveData, 'id' | 'name' | 'comment'> => {
  const {
    duration,
    eventUid,
    freq,
    interval,
    monthDays,
    scheduleTimezone,
    startDate,
    weekdays,
  } = state;

  if (
    !isDefined(data.id) ||
    !isDefined(startDate) ||
    data.timezone !== scheduleTimezone
  ) {
    return data;
  }

  const expectedCalendar = Event.fromData(
    {
      description: data.comment,
      duration,
      freq,
      interval: interval ?? 1,
      monthDays,
      startDate,
      summary: `${data.name}`,
      uid: eventUid,
      weekDays: weekdays,
    },
    data.timezone,
  ).toIcalString();

  if (data.icalendar !== expectedCalendar) {
    return data;
  }

  return {
    id: data.id,
    name: data.name,
    comment: data.comment,
  };
};

const ScheduleComponent = ({
  children,
  onCloned,
  onCloneError,
  onCreated,
  onCreateError,
  onDeleted,
  onDeleteError,
  onDownloaded,
  onDownloadError,
  onSaved,
  onSaveError,
}: ScheduleComponentProps) => {
  const gmp = useGmp();
  const [_] = useTranslation();
  const [timezone] = useUserTimezone();

  const [dialogVisible, setDialogVisible] = useState<boolean>(false);

  const [comment, setComment] = useState<string | undefined>();
  const [startDate, setStartDate] = useState<Date | undefined>();
  const [duration, setDuration] = useState<Duration | undefined>();
  const [eventUid, setEventUid] = useState<string | undefined>();
  const [freq, setFreq] = useState<RecurrenceFrequencyType | undefined>();
  const [id, setId] = useState<string | undefined>();
  const [interval, setInterval] = useState<number | undefined>();
  const [monthDays, setMonthDays] = useState<number[] | undefined>();
  const [name, setName] = useState<string | undefined>();
  const [title, setTitle] = useState<string | undefined>();
  const [scheduleTimezone, setScheduleTimezone] = useState<string | undefined>(
    timezone,
  );
  const [weekdays, setWeekdays] = useState<WeekDays | undefined>();

  const openCreateScheduleDialog = () => {
    setComment(undefined);
    setDialogVisible(true);
    setDuration(undefined);
    setEventUid(undefined);
    setFreq(undefined);
    setId(undefined);
    setInterval(undefined);
    setMonthDays(undefined);
    setName(undefined);
    setStartDate(undefined);
    setScheduleTimezone(timezone);
    setTitle(undefined);
    setWeekdays(undefined);
  };

  const openEditScheduleDialog = (schedule: Schedule) => {
    const {event} = schedule;
    if (!isDefined(event)) {
      return;
    }
    const {
      startDate: eventStartDate,
      recurrence,
      duration: eventDuration,
      durationInSeconds,
    } = event as Event;

    const {
      interval: recInterval,
      freq: recFreq,
      monthdays: recMonthdays,
      weekdays: recWeekdays,
    } = recurrence ?? {};

    setComment(schedule.comment);
    setStartDate(eventStartDate);
    setDialogVisible(true);
    setDuration(durationInSeconds > 0 ? eventDuration : undefined);
    setEventUid(event.event.uid);
    setFreq(recFreq);
    setId(schedule.id);
    setInterval(recInterval);
    setMonthDays(recMonthdays);
    setName(schedule.name);
    setTitle(_('Edit Schedule {{- name}}', {name: schedule.name as string}));
    setScheduleTimezone(schedule.timezone);
    setWeekdays(recWeekdays);
  };

  const closeScheduleDialog = () => {
    setDialogVisible(false);
  };

  const handleCloseScheduleDialog = () => {
    closeScheduleDialog();
  };

  return (
    <EntityComponent<Schedule>
      download={schedule => exportSchedule(gmp, schedule)}
      downloadOptions={{extension: 'json'}}
      name="schedule"
      onCloneError={onCloneError}
      onCloned={onCloned}
      onCreateError={onCreateError}
      onCreated={onCreated}
      onDeleteError={onDeleteError}
      onDeleted={onDeleted}
      onDownloadError={onDownloadError}
      onDownloaded={onDownloaded}
      onSaveError={onSaveError}
      onSaved={onSaved}
    >
      {({save, create, ...other}) => (
        <>
          {children({
            ...other,
            create: openCreateScheduleDialog,
            edit: openEditScheduleDialog,
          })}
          {dialogVisible && (
            <ScheduleDialog
              comment={comment}
              duration={duration}
              freq={freq}
              id={id}
              interval={interval}
              monthdays={monthDays}
              name={name}
              startDate={startDate}
              timezone={scheduleTimezone}
              title={title}
              weekdays={weekdays}
              onClose={handleCloseScheduleDialog}
              onSave={d => {
                const saveData = metadataOnlyScheduleSaveData(d, {
                  duration,
                  eventUid,
                  freq,
                  interval,
                  monthDays,
                  scheduleTimezone,
                  startDate,
                  weekdays,
                });
                const promise = isDefined(d.id) ? save(saveData) : create(d);
                return promise.then(() => closeScheduleDialog());
              }}
            />
          )}
        </>
      )}
    </EntityComponent>
  );
};

export default ScheduleComponent;
