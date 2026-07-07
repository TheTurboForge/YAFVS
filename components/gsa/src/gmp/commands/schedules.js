/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import registerCommand from 'gmp/command';
import EntitiesCommand from 'gmp/commands/entities';
import EntityCommand from 'gmp/commands/entity';
import {
  canUseNativeApi,
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import logger from 'gmp/log';
import Schedule from 'gmp/models/schedule';
import {
  cloneNativeSchedule,
  deleteNativeSchedule,
  exportNativeScheduleMetadata,
  exportNativeSchedulesMetadata,
  fetchNativeSchedules,
  nativeSchedulesQueryFromFilter,
  patchNativeSchedule,
} from 'gmp/native-api/schedules';

const log = logger.getLogger('gmp.commands.schedules');

const SCHEDULE_METADATA_SAVE_KEYS = new Set(['id', 'name', 'comment']);

const isScheduleMetadataOnlySave = args => {
  const keys = Object.keys(args);
  return (
    keys.every(key => SCHEDULE_METADATA_SAVE_KEYS.has(key)) &&
    typeof args.id === 'string' &&
    typeof args.name === 'string' &&
    (args.comment === undefined || typeof args.comment === 'string')
  );
};

const shouldExportAllByFilter = filter => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

export class ScheduleCommand extends EntityCommand {
  constructor(http) {
    super(http, 'schedule', Schedule);
  }

  create(args) {
    const {name, comment = '', icalendar, timezone} = args;
    log.debug('Creating new schedule', args);
    return this.action({
      cmd: 'create_schedule',
      name,
      comment,
      icalendar,
      timezone,
    });
  }

  save(args) {
    if (canUseNativeApi(this.http) && isScheduleMetadataOnlySave(args)) {
      return patchNativeSchedule(this.http, {
        id: args.id,
        name: args.name,
        comment: args.comment,
      });
    }

    const {comment = '', icalendar, id, name, timezone} = args;

    const data = {
      cmd: 'save_schedule',
      comment,
      id,
      icalendar,
      name,
      timezone,
    };
    log.debug('Saving schedule', args, data);
    return this.action(data);
  }

  getElementFromRoot(root) {
    return root.get_schedule.get_schedules_response.schedule;
  }

  async export({id}) {
    return await exportNativeScheduleMetadata(this.http, id);
  }

  async clone({id}) {
    if (canUseNativeApi(this.http)) {
      try {
        return await cloneNativeSchedule(this.http, id);
      } catch (error) {
        log.debug('Native schedule clone failed, falling back to GMP', error);
      }
    }
    return super.clone({id});
  }

  async delete({id}) {
    if (canUseNativeApi(this.http)) {
      await deleteNativeSchedule(this.http, id);
      return;
    }
    return super.delete({id});
  }
}

export class SchedulesCommand extends EntitiesCommand {
  constructor(http) {
    super(http, 'schedule', Schedule);
  }

  export(entities) {
    if (!canUseNativeApi(this.http)) {
      return super.export(entities);
    }

    return this.exportByIds(entities.map(entity => entity.id));
  }

  exportByIds(ids) {
    if (!canUseNativeApi(this.http)) {
      return super.exportByIds(ids);
    }

    return exportNativeSchedulesMetadata(this.http, ids);
  }

  async exportByFilter(filter) {
    if (!canUseNativeApi(this.http)) {
      return super.exportByFilter(filter);
    }

    const schedules = [];
    if (shouldExportAllByFilter(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; schedules.length < total; page += 1) {
        const nativeResponse = await fetchNativeSchedules(this.http, {
          ...nativeSchedulesQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        schedules.push(...nativeResponse.schedules);
        total = nativeResponse.page.total;
        if (nativeResponse.schedules.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativeSchedules(
        this.http,
        nativeSchedulesQueryFromFilter(filter),
      );
      schedules.push(...nativeResponse.schedules);
    }

    return exportNativeSchedulesMetadata(
      this.http,
      schedules.map(schedule => schedule.id),
    );
  }

  getEntitiesResponse(root) {
    return root.get_schedules.get_schedules_response;
  }
}

registerCommand('schedule', ScheduleCommand);
registerCommand('schedules', SchedulesCommand);
