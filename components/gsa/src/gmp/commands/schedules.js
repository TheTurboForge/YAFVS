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
  createNativeSchedule,
  deleteNativeSchedule,
  exportNativeScheduleMetadata,
  exportNativeSchedulesMetadata,
  fetchNativeSchedule,
  fetchNativeSchedules,
  nativeSchedulesQueryFromFilter,
  patchNativeSchedule,
} from 'gmp/native-api/schedules';

const log = logger.getLogger('gmp.commands.schedules');

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
    if (!canUseNativeApi(this.http)) {
      throw new Error('Native API is required to create schedules');
    }

    return createNativeSchedule(this.http, {
      name,
      comment,
      icalendar,
      timezone,
    });
  }

  save(args) {
    if (!canUseNativeApi(this.http)) {
      throw new Error('Native API is required to modify schedules');
    }

    return patchNativeSchedule(this.http, {
      id: args.id,
      name: args.name,
      comment: args.comment,
      icalendar: args.icalendar,
      timezone: args.timezone,
    });
  }

  getElementFromRoot(root) {
    return root.get_schedule.get_schedules_response.schedule;
  }

  async get({id}, {filter, ...options} = {}) {
    if (canUseNativeApi(this.http)) {
      if (nativeScheduleDetailSupportsFilter(filter)) {
        return new Response(await fetchNativeSchedule(this.http, id));
      }
      throw new Error('Native schedule detail filter is not supported');
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
