/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import registerCommand from 'gmp/command';
import EntitiesCommand from 'gmp/commands/entities';
import EntityCommand from 'gmp/commands/entity';
import {canUseNativeApi} from 'gmp/commands/native';
import logger from 'gmp/log';
import Schedule from 'gmp/models/schedule';
import {cloneNativeSchedule} from 'gmp/native-api/schedules';

const log = logger.getLogger('gmp.commands.schedules');

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
}

export class SchedulesCommand extends EntitiesCommand {
  constructor(http) {
    super(http, 'schedule', Schedule);
  }

  getEntitiesResponse(root) {
    return root.get_schedules.get_schedules_response;
  }
}

registerCommand('schedule', ScheduleCommand);
registerCommand('schedules', SchedulesCommand);
