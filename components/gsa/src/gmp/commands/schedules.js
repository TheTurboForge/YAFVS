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
import Response from 'gmp/http/response';
import logger from 'gmp/log';
import {filterString} from 'gmp/models/filter/utils';
import Schedule from 'gmp/models/schedule';
import {
  cloneNativeSchedule,
  deleteNativeSchedule,
  exportNativeScheduleMetadata,
  exportNativeSchedulesMetadata,
  fetchNativeSchedule,
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

const nativeScheduleDetailSupportsFilter = filter => {
  const value = filterString(filter);
  return filter === undefined || value === 'tasks=1' || value === 'alerts=1';
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

  async get({id}, {filter, ...options} = {}) {
    if (canUseNativeApi(this.http) && nativeScheduleDetailSupportsFilter(filter)) {
      return new Response(await fetchNativeSchedule(this.http, id));
    }
    return super.get({id}, {filter, ...options});
  }

  async export({id}) {
    return await exportNativeScheduleMetadata(this.http, id);
  }

  async clone({id}) {
    if (canUseNativeApi(this.http)) {
      return await cloneNativeSchedule(this.http, id);
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
    return this.exportByIds(entities.map(entity => entity.id));
  }

  exportByIds(ids) {
    return exportNativeSchedulesMetadata(this.http, ids);
  }

  async exportByFilter(filter) {
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
